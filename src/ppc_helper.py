import angr
import sys
import archinfo
import tempfile
from pathlib import Path
import os
import pickle

split_str = "</compatibility_header>"
arch = "PowerPC:BE:32:MPC8270"

myRegions = None
def run_project(xcal_path):
    out_file_path = xcal_path + "_temp.xcal"
    out_file_pickle_path = out_file_path + ".project.p"
    # If temp file already exist, load a *.project.p file,
    # otherwise, create a new project and dump it to a *.project.p file
    if os.path.exists(out_file_pickle_path):
        project = pickle.load(open(out_file_pickle_path, "rb"))

    else:
        project = create_project(xcal_path, out_file_path)
    return project

def create_project(xcal_path, out_file_path):
    data = Path(xcal_path).read_text().split(split_str)[-1].strip()
    with open(out_file_path, mode="w+") as fp:
        fp.write(data)
        path = fp.name
        project = angr.Project(path,
                                arch=archinfo.ArchPcode(arch),
                                auto_load_libs=False,
                                load_debug_info=True,
                                main_opts={'backend': 'hex'})
    return project

def get_p_and_cfg(project):
    filename = project.filename
    cfg_pickle_path = filename + ".cfg.p"
    # If cfg pickle file already exist, load it,
    # otherwise, create a new cfg and dump it to a *.cfg.p file
    if os.path.exists(cfg_pickle_path):
        cfg = pickle.load(open(cfg_pickle_path, "rb"))
    else:
        cfg = project.analyses.CFGFast(exclude_sparse_regions=False,
                                show_progressbar=True,
                                resolve_indirect_jumps=True,
                                data_references=True,
                                cross_references=False,
                                skip_unmapped_addrs=True,
                                normalize=True,
                                force_smart_scan=False,
                                force_complete_scan=False)
        # pickle.dump(cfg, open(cfg_pickle_path, "wb"))
        # print(cfg.kb.functions._function_map)
    return project, cfg