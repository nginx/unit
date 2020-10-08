import os


def check_node(current_dir):
    if os.path.exists(current_dir + '/node/node_modules'):
        return True
