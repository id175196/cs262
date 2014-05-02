import pickle

#pickle and load merkle trees

def pickle_data(mt, filename):
    """pickle data and store in the given filename."""
    handle = open(filename, 'wb')
    pickle.dump(a, handle)
    handle.close()
    return

def unpickle_data(filename):
    """unpickle a data file stored in the given filename."""
    handle = open(filename, 'rb')
    return pickle.load(handle)
