import os
import logging

import angr

l = logging.getLogger('patcherex.backend')

FIND_FUNCS = (
    'malloc',
    'printf',
    'fdprintf',
    'fprintf',
    'sprintf',
    'snprintf',
)

class Backend(object):
    """
    Patcher backend.
    """

    def __init__(self, filename, try_pdf_removal=True, custom_base_addr=None):
        """
        Constructor

        :param str filename: The binary file to patch
        """

        # file info
        self.filename = filename
        self.try_pdf_removal = try_pdf_removal
        self.pdf_removed = False # has the pdf actually been removed?
        if custom_base_addr is None:
            self.project = angr.Project(filename, load_options = {'auto_load_libs': False})
        else:
            self.project = angr.Project(filename, load_options = {'auto_load_libs': False, 'main_opts': {'custom_base_addr': custom_base_addr}})
        self._identifer = None
        with open(filename, "rb") as f:
            self.ocontent = f.read()

    #
    # Public methods
    #

    def apply_patches(self, patches):
        """
        Apply all patches on this binary

        :param list patches: A list of patches to apply
        :return: None
        """

        raise NotImplementedError()

    def save(self, filename=None):
        """
        Save the patched binary onto disk.

        :param str filename: The new file path to save to. If None, the original binary will be overwritten.
        :return: None
        """

        raise NotImplementedError()

    def get_final_content(self):
        """
        Get the patched binary as a byte string.

        :return: The patched binary as a byte string.
        :rtype: str
        """

        raise NotImplementedError()

    @property
    def identifier(self):
        if self._identifer is None:
            self._identifer = self.project.analyses.Identifier(self.cfg, require_predecessors=False)
            list(self._identifer.run(only_find=FIND_FUNCS))
        return self._identifer



    #
    # Private methods
    #

    def _generate_cfg(self):
        """
        Generate a control flow graph, make sure necessary steps are performed, and return a CFG.

        :return: The CFG object
        :rtype: angr.analyses.CFG
        """

        # TODO
        # 1) ida-like cfg
        # 2) with some strategies we don't need the cfg, we should be able to apply those strategies even if the cfg fails
        l.info("CFG start...")
        if "CFG_ACCURATE" in os.environ:
            cfg = self.project.analyses.CFGAccurate(keep_state=True, enable_advanced_backward_slicing=True)
        else:
            cfg = self.project.analyses.CFGFast(normalize=True, collect_data_references=True)

        # Fix bugs of angr cfg using IDA
        # prevent error 
        if "IDA_PATH" in os.environ:
            if cfg.ida_func_info:
                # Convert format into dict
                start_end_map = dict((x,y) for x, y in cfg.ida_func_info)

                for k,ff in cfg.functions.iteritems():
                    if ff.startpoint is None:
                        continue
                    start = ff.startpoint.addr
                    if not start in start_end_map:
                        # l.warn("%s (at %s) is not in IDA information", ff.name, hex(start))
                        continue
                    ida_end = start_end_map[start]

                    ret_sites_to_remove = []
                    for ret_site in ff.ret_sites:
                        ret_site_addr = ret_site.addr
                        if ret_site_addr > ida_end:
                            l.warn("Remove ret_site (%s)  at %s that is higher than ida end (%s)",
                                    hex(ret_site_addr), ff.name, hex(ida_end))
                            ret_sites_to_remove.append(ret_site)

                    for ret_site in ret_sites_to_remove:
                        # XXX: we touch internal data of function definition in angr
                        # which may cause some problems
                        ff._ret_sites.remove(ret_site)

        l.info("... CFG end")
        return cfg

    def _get_ordered_nodes(self, cfg):
        prev_addr = None
        ordered_nodes = []
        for n in sorted(cfg.nodes(), key=lambda x: x.addr):
            if n.addr == prev_addr:
                continue
            prev_addr = n.addr
            ordered_nodes.append(n.addr)
        return ordered_nodes
