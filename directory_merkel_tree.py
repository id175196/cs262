import os
from os import path
from os import listdir
from os.path import isdir, isfile
from hashlib import sha256

empty_directory_hash = sha256('empty directory').digest()

def make_dmt(root_directory=os.getcwd(), nonce='', encrypter=None):
  if not isdir(root_directory):
    raise IOError('The root directory supplied, \'{}\', is not in fact a directory.'.format(root_directory))
  
  directory_contents = listdir(root_directory)
  
  if not directory_contents:
    return DirectoryMerkelTree(dmt_hash=empty_directory_hash, children=None)
    
  children = dict()
  
  for filesystem_item in directory_contents:
    item_path = path.join(root_directory, filesystem_item)
    
    if isfile(item_path):
      filename = filesystem_item
      file_path = path.join(root_directory, filename)
      with open(file_path, 'r') as f:
        file_contents = f.read()
      
      if encrypter:
        filename = encrypter.encrypt_filename(filename)
        file_contents = encrypter.encrypt(file_contents)
      
      file_hash = sha256(file_contents)
      
      if nonce:
        file_hash.update(nonce)
        
      dmt_child = DirectoryMerkelTree(dmt_hash=file_hash.digest(), children=None)
      children[filename] = dmt_child
      
    elif isdir(item_path):
      subdir_name = filesystem_item
      subdir_path = path.join(root_directory, subdir_name)
      
      dmt_subtree = make_dmt(subdir_path, nonce, encrypter)
      
      if encrypter:
        subdir_name = encrypter.encrypt_filename(subdir_name)
        
      # Append a slash to facilitate detection of new empty folders upon comparison.
      subdir_name += '/'
      
      children[subdir_name] = dmt_subtree
      
    # Item was neither file nor directory...
    else:
      raise IOError('Item \'{}\' is neither a file nor directory.'.format(item_path))
      
  # Compile all child hashes to compute this tree's hash.
  tree_hash = sha256()
  for child in children.values():
    tree_hash.update(child.dmt_hash)
    
  dmt_tree = DirectoryMerkelTree(dmt_hash=tree_hash.digest(), children=children)
  return dmt_tree

def print_tree(tree):
  
  if tree.children:
    print 'Directory hash = {}'.format(tree.dmt_hash)
    print 'Contents:'
    for name, subtree in tree.children.iteritems():
      print
      print name
      print_tree(subtree)
  
  else:
    print 'File hash = {}'.format(tree.dmt_hash)

def compute_tree_changes(dmt_new, dmt_old, directory_path=''):
  updated, new, deleted = set(), set(), set()
  # Base cases:
  # Both files or empty directories
  if (not dmt_new.children) and (not dmt_old.children):
    return updated, new, deleted
  # New directory
  elif not not dmt_old.children:
    mutual_filesystem_items = set()
    new_filesystem_items = set(dmt_new.children.keys())
    deleted_filesystem_items = set()
  elif not dmt_new.children:
    mutual_filesystem_items = set()
    new_filesystem_items = set()
    deleted_filesystem_items = set(dmt_old.children.keys())
  else:
    mutual_filesystem_items   = set(dmt_new.children.keys()).intersection(set(dmt_old.children.keys()))
    new_filesystem_items      = set(dmt_new.children.keys()).difference(set(dmt_old.children.keys()))
    deleted_filesystem_items  = set(dmt_old.children.keys()).difference(set(dmt_new.children.keys()))
  
  
  # Compile the set of updated files and directories, as well as any other changes within subdirectories.
  for filesystem_item in mutual_filesystem_items:
    # Always check subdirectories for e.g file renamings.
    if filesystem_item[-1] == '/':
      subdir_name = filesystem_item
      subdir_path = directory_path + subdir_name
      subdir_updated, subdir_new, subdir_deleted = \
          compute_tree_changes(dmt_new.children[subdir_name], dmt_old.children[subdir_name], subdir_path)
      
      # Mark the subdirectory if necessary.
      if (dmt_old.children[subdir_name].dmt_hash != dmt_new.children[subdir_name].dmt_hash) or \
          subdir_updated or subdir_new or subdir_deleted:
        updated.add(subdir_path)
      
      # Incorporate differences from within.
      updated.update(subdir_updated)
      new.update(subdir_new)
      deleted.update(subdir_deleted)
    
    # File with differing hash values.
    elif dmt_old.children[filesystem_item].dmt_hash != dmt_new.children[filesystem_item].dmt_hash:
      filename = filesystem_item
      file_path = directory_path + filename
      updated.add(file_path)
  
  # Compile the set of newly created files.
  for filesystem_item in new_filesystem_items:
    item_path = directory_path + filesystem_item
    new.add(item_path)
    new.update(get_all_paths(dmt_new.children[filesystem_item], directory_path))
    
  # Compile the set of deleted files.
  for filesystem_item in deleted_filesystem_items:
    item_path = directory_path + filesystem_item
    deleted.add(item_path)
    deleted.update(get_all_paths(dmt_old.children[filesystem_item], directory_path))
  
  return updated, new, deleted

def get_all_paths(dmt, directory_path=''):
  # Base case.
  if not dmt.children:
    return set()
  
  filesystem_items = set()
  for item in dmt.children.keys():
    filesystem_items.add(directory_path+item)
    # Also get the paths of subdirectory contents.
    if item[-1] == '/':
      subdir_name = item
      subdir_path = directory_path + subdir_name
      
      filesystem_items.add(subdir_path)
      filesystem_items.update(get_all_paths(dmt.children[subdir_name], subdir_path))
    
  return filesystem_items
  

class DirectoryMerkelTree:
  def __init__(self, dmt_hash, children):
    self.dmt_hash = dmt_hash
    self.children = children
  
  def __eq__(self, other):
    if not other:
      return False
    
    if type(other) is not type(self):
      raise TypeError('{} is not equal to {}'.format(type(self), type(other)))
    
    updated, new, deleted = compute_tree_changes(self, other)
    
    if updated or new or deleted:
      return False
    else:
      return True
    
  def __ne__(self, other):
    return not (self == other)
    
  def compare_trees(self):
    None
  
  def get_updated_tree(self):
    None

if __name__ == '__main__':
  tree = make_dmt(os.path.join(os.getcwd(), 'personal/'))
  print get_all_paths(tree)
  print_tree(tree)
  
  tree_a = make_dmt(os.path.join(os.getcwd(), 'testA/'))
  tree_b = make_dmt(os.path.join(os.getcwd(), 'testB/'))
  
  assert tree_a != tree_b
  
  changes_a_b = compute_tree_changes(tree_a, tree_b)
  changes_b_a = compute_tree_changes(tree_b, tree_a)
  print changes_a_b
  print changes_b_a
  
  nonce = 'a testing nonce'
  tree_a_nonced = make_dmt(os.path.join(os.getcwd(), 'testA/'), nonce=nonce)
  tree_b_nonced = make_dmt(os.path.join(os.getcwd(), 'testB/'), nonce=nonce)
  
  assert tree_a_nonced == make_dmt(os.path.join(os.getcwd(), 'testA/'), nonce=nonce)
  assert tree_a != tree_a_nonced
  
  changes_a_b_nonced = compute_tree_changes(tree_a_nonced, tree_b_nonced)
  assert changes_a_b_nonced == changes_a_b
  
  print 'All tests passed!'