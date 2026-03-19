import subprocess
import os
import csv
from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter

BUILD_ERROR_COMMITS = []
OTHER_ERROR_COMMITS = []
ERROR_COMMITS_INFO = []
VALID_LIBS = ['libavcodec', 'libavformat', 'libavutil', 'libavfilter', 'libdevice', 'libswresample', 'libswscale']
VALID_BINS = ['ffmpeg', 'ffserver', 'ffplay', 'ffprobe']

BENCHMARK_NAME = "patchdb_ffmpeg"


def get_target_filename(lib_or_bin):
    """Get the output filename for a given library or binary name."""
    return f"{lib_or_bin}.so" if lib_or_bin in VALID_LIBS else lib_or_bin


def build_patch(build_dir, index, commit, lib_or_bin):
    """Build pre-patch and post-patch unstripped binaries for a given commit."""
    if lib_or_bin not in VALID_LIBS + VALID_BINS:
        print(f"Commit {commit} does not affect a valid library/binary ({lib_or_bin}), skipping...")
        return False

    if os.path.exists(os.path.join(build_dir, commit)):
        print(f"Build directory for commit {commit} already exists, skipping...")
        return True

    container_name = f"{BENCHMARK_NAME}_container_{commit}"
    image_name = f"{BENCHMARK_NAME}_{commit}"
    try:
        subprocess.run(["docker", "build",
                        "--build-arg", f"COMMIT_SHA={commit}",
                        "-t", image_name, "-f", "Dockerfile", "."], check=True)
        subprocess.run(["docker", "run", "--name", container_name, image_name], check=True)

        filename = get_target_filename(lib_or_bin)

        os.makedirs(os.path.join(build_dir, commit, "original"), exist_ok=True)
        os.makedirs(os.path.join(build_dir, commit, "patched"), exist_ok=True)
        subprocess.run(["docker", "cp", f"{container_name}:/build/original/{filename}",
                        os.path.join(build_dir, commit, "original")], check=True)
        subprocess.run(["docker", "cp", f"{container_name}:/build/patched/{filename}",
                        os.path.join(build_dir, commit, "patched")], check=True)

        subprocess.run(["docker", "rm", container_name], check=True)
        subprocess.run(["docker", "rmi", image_name], check=True)
        return True

    except Exception as e:
        print(f"An error occurred: {e}")
        if commit not in BUILD_ERROR_COMMITS:
            BUILD_ERROR_COMMITS.append(commit)
            ERROR_COMMITS_INFO.append((index, commit, e))
        subprocess.run(["docker", "rm", container_name], check=False, capture_output=True)
        subprocess.run(["docker", "rmi", image_name], check=False, capture_output=True)
        return False


def copy_and_strip_binaries(unstripped_dir, stripped_dir, index, commit, lib_or_bin):
    """Copy from unstripped build directory and strip the binaries."""
    if lib_or_bin not in VALID_LIBS + VALID_BINS:
        print(f"Commit {commit} does not affect a valid library/binary ({lib_or_bin}), skipping...")
        return False

    if os.path.exists(os.path.join(stripped_dir, commit)):
        print(f"Stripped directory for commit {commit} already exists, skipping...")
        return True

    filename = get_target_filename(lib_or_bin)
    try:
        os.makedirs(os.path.join(stripped_dir, commit, "original"), exist_ok=True)
        os.makedirs(os.path.join(stripped_dir, commit, "patched"), exist_ok=True)

        subprocess.run(["cp",
                        os.path.join(unstripped_dir, commit, "original", filename),
                        os.path.join(stripped_dir, commit, "original", filename)], check=True)
        subprocess.run(["cp",
                        os.path.join(unstripped_dir, commit, "patched", filename),
                        os.path.join(stripped_dir, commit, "patched", filename)], check=True)

        subprocess.run(["strip", "-s",
                        os.path.join(stripped_dir, commit, "original", filename)], check=True)
        subprocess.run(["strip", "-s",
                        os.path.join(stripped_dir, commit, "patched", filename)], check=True)
        print(f"Done copying and stripping commit: {commit}")
        return True

    except Exception as e:
        print(f"An error occurred: {e}")
        if commit not in BUILD_ERROR_COMMITS:
            BUILD_ERROR_COMMITS.append(commit)
            ERROR_COMMITS_INFO.append((index, commit, e))
        try:
            commit_dir = os.path.join(stripped_dir, commit)
            original_dir = os.path.join(commit_dir, "original")
            patched_dir = os.path.join(commit_dir, "patched")
            if os.path.exists(commit_dir):
                if os.path.exists(original_dir) and not os.listdir(original_dir):
                    os.rmdir(original_dir)
                if os.path.exists(patched_dir) and not os.listdir(patched_dir):
                    os.rmdir(patched_dir)
                if not os.listdir(commit_dir):
                    os.rmdir(commit_dir)
        except Exception as e_rm:
            print(f"An error occurred during cleanup: {e_rm}")
        return False


def build_patches_from_csv(csv_path, build_dir, limit=None):
    """Build unstripped binaries via Docker, then copy+strip to produce stripped versions."""
    unstripped_dir = os.path.join(build_dir, "unstripped")
    stripped_dir = os.path.join(build_dir, "stripped")
    os.makedirs(unstripped_dir, exist_ok=True)
    os.makedirs(stripped_dir, exist_ok=True)

    with open(csv_path, 'r') as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    if limit is not None:
        rows = rows[:limit]

    total = len(rows)
    for index, row in enumerate(rows):
        commit = None
        try:
            commit = row['commit_hash'].strip()
            if commit == "":
                continue
            lib_or_bin = row['affected_libs_or_binary'].strip()

            print(f"[{index+1}/{total}] Building unstripped: {commit}...")
            success = build_patch(unstripped_dir, index, commit, lib_or_bin)

            if success:
                print(f"[{index+1}/{total}] Stripping: {commit}...")
                copy_and_strip_binaries(unstripped_dir, stripped_dir, index, commit, lib_or_bin)

        except Exception as e:
            print(f"An error occurred: {e}")
            if commit and commit not in OTHER_ERROR_COMMITS:
                OTHER_ERROR_COMMITS.append(commit)
                ERROR_COMMITS_INFO.append((index, commit, e))
            continue


if __name__ == "__main__":
    parser = ArgumentParser(formatter_class=ArgumentDefaultsHelpFormatter)
    parser.add_argument('--csv_path', default="patchdb_ffmpeg.csv", help='CSV path')
    parser.add_argument('--build_dir', required=True, help='Build directory (creates unstripped/ and stripped/ subfolders)')
    parser.add_argument('--limit', type=int, default=None, help='Only process the first N commits')
    args = parser.parse_args()

    if not os.path.exists(args.csv_path):
        print(f"CSV path {args.csv_path} does not exist")
        exit(1)

    os.makedirs(args.build_dir, exist_ok=True)

    build_patches_from_csv(args.csv_path, args.build_dir, limit=args.limit)

    if ERROR_COMMITS_INFO:
        print("\n[+] Commits that failed to build:")
        for (index, commit, e) in ERROR_COMMITS_INFO:
            print(f"  Index: {index}, Commit: {commit}, Error: {e}")
