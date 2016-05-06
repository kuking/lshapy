#!/usr/bin/env python3

import argparse, os, hashlib

pargs = argparse.ArgumentParser(description='List files and folders renovated. Useful to verify is things have changed.')
pargs.add_argument('-c', default=False, dest='checksum', action='store_const', const=True, help='checksum files')
pargs.add_argument('-r', default=False, dest='recursive', action='store_const', const=True, help='walk recursively')
pargs.add_argument('-i', default=False, dest='hidden', action='store_const', const=True, help='include hidden files')
pargs.add_argument('-t', default=False, dest='recursive', action='store_const', const=True, help='include timestamps')
pargs.add_argument('-x', default=False, dest='xattrs', action='store_const', const=True, help='include xattrs')
pargs.add_argument('-p', default=False, dest='perms', action='store_const', const=True, help='include permissions')
pargs.add_argument('-a', default=False, dest='all', action='store_const', const=True, help='include everything')
pargs.add_argument('--algo:md5', dest='algo', action='store_const', const='md5', help='checksum will be md5')
pargs.add_argument('--algo:sha1', dest='algo', action='store_const', const='sha1', help='checksum will be sha1')
pargs.add_argument('--algo:sha256', dest='algo', action='store_const', const='sha256', help='checksum will be sha256 (default)')
pargs.add_argument('--algo:sha512', dest='algo', action='store_const', const='sha512', help='checksum will be sha512')

pargs.add_argument('path', type=str, help='path to list')
arguments = pargs.parse_args()


def is_hidden(path):
    name = os.path.basename(os.path.abspath(path))
    return name.startswith('.')


def do_checksum(args, fullpath):
    if args.algo == 'md5':
        h = hashlib.md5()
    elif args.algo == 'sha1':
        h = hashlib.sha1()
    elif args.algo == 'sha512':
        h = hashlib.sha512()
    else: # default
        h = hashlib.sha256()
    with open(fullpath, 'rb') as f:
        for chunk in iter(lambda: f.read(8096), b""):
            h.update(chunk)
    return h.hexdigest()


def do_file(args, path, filename):
    fullpath = "%s/%s" % (path, filename)
    if is_hidden(fullpath) and not (args.hidden or args.all):
        return

    if args.checksum or args.all:
        checksum = do_checksum(args, fullpath)
    else:
        checksum = ''

    print('%s %s' % (checksum, filename))


def do_path(args, path):
    if is_hidden(path) and not (args.hidden or args.all):
        return
    for dirpath, dirnames, filenames in os.walk(path):
        print('>', dirpath)
        if len(dirnames) > 0:
            print('>>', ', '.join(dirnames))

        for filename in filenames:

            do_file(args, dirpath, filename)
        print()

        if not (args.recursive or args.all):
            break



# main

if os.path.isfile(arguments.path):
    do_file(arguments, arguments.path)
else:
    do_path(arguments, arguments.path)
