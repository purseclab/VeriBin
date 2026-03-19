# FFmpeg Patch Builder

Build pre-patch and post-patch FFmpeg binaries (both unstripped and stripped) from [PatchDB](https://sunlab-gmu.github.io/PatchDB/) commits.

## Files
- `Dockerfile` — Builds unstripped original and patched FFmpeg binaries for a given commit.
- `build_all.py` — Batch-builds all commits from the CSV, producing both unstripped and stripped binaries.
- `patchdb_ffmpeg.csv` — 56 FFmpeg patches from PatchDB used in the paper.

## Usage

### Batch build

```bash
python build_all.py --build_dir <output_dir>
python build_all.py --build_dir <output_dir> --limit 3  # only first 3 commits
```

Creates `<output_dir>/unstripped/` and `<output_dir>/stripped/`. For each commit, builds unstripped binaries via Docker, then copies and strips them.

### Single commit

```bash
docker build --build-arg COMMIT_SHA=<COMMIT_SHA> -t <image_name> -f Dockerfile .
docker run --name tmp <image_name>
docker cp tmp:/build/original/<file> ./original/
docker cp tmp:/build/patched/<file> ./patched/
docker rm tmp && docker rmi <image_name>
```
