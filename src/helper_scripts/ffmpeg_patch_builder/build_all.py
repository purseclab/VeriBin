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


def build_patch(build_dir, index, commit, lib_or_bin, strip_mode):
    """Build pre-patch and post-patch binaries for a given commit."""
    if lib_or_bin not in VALID_LIBS + VALID_BINS:
        print(f"Commit {commit} does not affect a valid library/binary ({lib_or_bin}), skipping...")
        return False

    # If the build directory for the commit already exists, skip it
    if os.path.exists(os.path.join(build_dir, commit)):
        print(f"Build directory for commit {commit} already exists, skipping...")
        return True

    container_name = f"{BENCHMARK_NAME}_container_{commit}"
    image_name = f"{BENCHMARK_NAME}_{commit}"
    try:
        # Build the Docker image with the specified commit
        subprocess.run(["docker", "build",
                        "--build-arg", f"COMMIT_SHA={commit}",
                        "--build-arg", f"STRIP_MODE={strip_mode}",
                        "-t", image_name, "-f", "Dockerfile", "."], check=True)

        # Run the Docker container
        subprocess.run(["docker", "run", "--name", container_name, image_name], check=True)

        # Determine the filename to copy (shared lib vs binary)
        filename = f"{lib_or_bin}.so" if lib_or_bin in VALID_LIBS else lib_or_bin

        # Copy built files from the container
        os.makedirs(os.path.join(build_dir, commit, "original"), exist_ok=True)
        os.makedirs(os.path.join(build_dir, commit, "patched"), exist_ok=True)
        subprocess.run(["docker", "cp", f"{container_name}:/build/original/{filename}",
                        os.path.join(build_dir, commit, "original")], check=True)
        subprocess.run(["docker", "cp", f"{container_name}:/build/patched/{filename}",
                        os.path.join(build_dir, commit, "patched")], check=True)

        # Remove the Docker container and image (check=False to avoid failing on cleanup)
        subprocess.run(["docker", "rm", container_name], check=True)
        subprocess.run(["docker", "rmi", image_name], check=True)
        return True

    except Exception as e:
        print(f"An error occurred: {e}")
        if commit not in BUILD_ERROR_COMMITS:
            BUILD_ERROR_COMMITS.append(commit)
            ERROR_COMMITS_INFO.append((index, commit, e))
        # Best-effort cleanup (check=False so cleanup failures don't raise)
        subprocess.run(["docker", "rm", container_name], check=False, capture_output=True)
        subprocess.run(["docker", "rmi", image_name], check=False, capture_output=True)
        return False


def build_patches_from_csv(csv_path, build_dir, strip_mode):
    """Iterate over the CSV and build each commit."""
    with open(csv_path, 'r') as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames
        rows = list(reader)


    total = len(rows)
    for index, row in enumerate(rows):
        try:
            if row['status'].strip() == 'n':
                continue
            commit = row['commit_hash'].strip()
            if commit == "":
                continue
            lib_or_bin = row['affected_libs_or_binary'].strip()
            print(f"[{index+1}/{total}] Processing {commit}...")
            build_patch(build_dir, index, commit, lib_or_bin, strip_mode)
        except Exception as e:
            print(f"An error occurred: {e}")
            if commit not in OTHER_ERROR_COMMITS:
                OTHER_ERROR_COMMITS.append(commit)
                ERROR_COMMITS_INFO.append((index, commit, e))
            continue

    # Mark failed commits in the CSV
    if BUILD_ERROR_COMMITS:
        for row in rows:
            if row['commit_hash'] in BUILD_ERROR_COMMITS and row['status'] != 'n':
                row['status'] = 'n'
        with open(csv_path, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)


if __name__ == "__main__":
    parser = ArgumentParser(formatter_class=ArgumentDefaultsHelpFormatter)
    parser.add_argument('--csv_path', default="patchDB_ffmpeg.csv", help='CSV path')
    parser.add_argument('--build_dir', required=True, help='Build directory')
    parser.add_argument('--strip_mode', choices=['stripped', 'unstripped'], default='unstripped',
                        help='Build stripped or unstripped binaries')
    args = parser.parse_args()

    if not os.path.exists(args.csv_path):
        print(f"CSV path {args.csv_path} does not exist")
        exit(1)

    os.makedirs(args.build_dir, exist_ok=True)

    build_patches_from_csv(args.csv_path, args.build_dir, args.strip_mode)

    if ERROR_COMMITS_INFO:
        print("\n[+] Commits that failed to build:")
        for (index, commit, e) in ERROR_COMMITS_INFO:
            print(f"  Index: {index}, Commit: {commit}, Error: {e}")