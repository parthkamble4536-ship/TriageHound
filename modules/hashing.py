import hashlib
import os

def hash_file(filepath):
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    with open(filepath, 'rb') as f:
        while chunk := f.read(8192):  # read in chunks - handles large files
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)

    return {
        'filepath': filepath,
        'md5': md5.hexdigest(),
        'sha1': sha1.hexdigest(),
        'sha256': sha256.hexdigest(),
        'file_size': os.path.getsize(filepath)
    }
