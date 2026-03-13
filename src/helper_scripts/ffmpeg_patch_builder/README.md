# FFmpeg Patch Builder

Dockerfile and build script for building pre-patch and post-patch FFmpeg binaries from [PatchDB](https://sunlab-gmu.github.io/PatchDB/) commits. Given a commit SHA, it clones the FFmpeg repository, builds the **patched** version (at the specified commit) and the **original** version (at `HEAD~1`), producing shared libraries (`.so`) and binaries under `/build/patched/` and `/build/original/` respectively.

## Folder Structure
- `Dockerfile` — Builds both original and patched FFmpeg binaries for a given commit.
- `build_all.py` — Script to batch-build all commits listed in the CSV.
- `patchDB_ffmpeg.csv` — List of FFmpeg commits from PatchDB with affected libraries/binaries.

## Usage

### Single commit (Dockerfile directly)

```bash
# Unstripped (default)
docker build --build-arg COMMIT_SHA=<COMMIT_SHA> -t <image_name> -f Dockerfile .

# Stripped
docker build --build-arg COMMIT_SHA=<COMMIT_SHA> --build-arg STRIP_MODE=stripped -t <image_name> -f Dockerfile .
```

To extract the built binaries from the container:

```bash
docker run --name ffmpeg_build <image_name>
docker cp ffmpeg_build:/build/patched/<specific_file> ./patched/<specific_file>
docker cp ffmpeg_build:/build/original/<specific_file> ./original/<specific_file>
docker rm ffmpeg_build
docker rmi <image_name>
```

### Batch build (all commits from CSV)

```bash
python build_all.py --build_dir <output_dir>

# With options
python build_all.py --build_dir <output_dir> --strip_mode stripped --csv_path patchDB_ffmpeg.csv
```
