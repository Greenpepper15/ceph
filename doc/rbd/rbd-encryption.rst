======================
 Image Encryption
======================

.. index:: Ceph Block Device; encryption

Starting with the Pacific release, image-level encryption can be handled
internally by RBD clients. This means you can set a secret key that will be
used to encrypt a specific RBD image. This page describes the scope of the
RBD encryption feature.

.. note::
   The ``krbd`` kernel module does not support encryption at this time.

.. note::
   External tools (e.g. dm-crypt, QEMU) can be used as well to encrypt
   an RBD image, and the feature set and limitation set for that use may be
   different than described here.

Encryption Format
=================

By default, RBD images are not encrypted. To encrypt an RBD image, it needs to
be formatted to one of the supported encryption formats. The format operation
persists encryption metadata to the image. The encryption metadata usually
includes information such as the encryption format and version, cipher
algorithm and mode specification, as well as information used to secure the
encryption key. The encryption key itself is protected by a user-kept secret
(usually a passphrase), which is never persisted. The basic encryption format
operation will require specifying the encryption format and a secret.

Some of the encryption metadata may be stored as part of the image data,
typically an encryption header will be written to the beginning of the raw
image data. This means that the effective image size of the encrypted image may
be lower than the raw image size. See the `Supported Formats`_ section for more
details.

.. note::
   Unless explicitly (re-)formatted, clones of an encrypted image are
   inherently encrypted using the same format and secret.

.. note::
   Clones of an encrypted image are always encrypted.
   Re-formatting to plaintext is not supported.

.. note::
   Any data written to the image prior to its format may become unreadable,
   though it may still occupy storage resources.

.. note::
   Images with the `journal feature`_ enabled cannot be formatted and encrypted
   by RBD clients.

Encryption Load
=================

Formatting an image is a necessary pre-requisite for enabling encryption.
However, formatted images will still be treated as raw unencrypted images by
all of the RBD APIs. In particular, an encrypted RBD image can be opened
by the same APIs as any other image, and raw unencrypted data can be
read / written. Such raw I/Os may risk the integrity of the encryption format,
for example by overriding encryption metadata located at the beginning of the
image.

In order to safely perform encrypted I/O on the formatted image, an additional
*encryption load* operation should be applied after opening the image. The
encryption load operation requires supplying the encryption format and a secret
for unlocking the encryption key for the image itself and each of its explicitly
formatted ancestor images. Following a successful encryption load operation,
all I/Os for the opened image will be encrypted / decrypted. For a cloned
image, this includes I/Os for ancestor images as well. The encryption keys will
be stored in-memory by the RBD client until the image is closed.

.. note::
   Once encryption has been loaded, no other encryption load / format
   operations can be applied to the context of the opened image.

.. note::
   Once encryption has been loaded, API calls for retrieving the image size
   and the parent overlap using the opened image context will return the
   effective image size and the effective parent overlap respectively.

.. note::
   Once encryption has been loaded, API calls for resizing the image will
   interpret the specified target size as effective image size.

.. note::
   If a clone of an encrypted image is explicitly formatted, the operation of
   flattening the cloned image ceases to be transparent since the parent data
   must be re-encrypted according to the cloned image format as it is copied
   from the parent snapshot. If encryption is not loaded before the flatten
   operation is issued, any parent data that was previously accessible in the
   cloned image may become unreadable.

.. note::
   If a clone of an encrypted image is explicitly formatted, the operation of
   shrinking the cloned image ceases to be transparent since in some cases
   (e.g. if the cloned image has snapshots or if the cloned image is being
   shrunk to a size that is not aligned with the object size) it involves
   copying some data from the parent snapshot, similar to flattening. If
   encryption is not loaded before the shrink operation is issued, any parent
   data that was previously accessible in the cloned image may become
   unreadable.

.. note::
   Encryption load can be automatically applied when mounting RBD images as
   block devices via `rbd-nbd`_.

Supported Formats
=================

LUKS
~~~~~~~

Both LUKS1 and LUKS2 are supported. The data layout is fully compliant with the
LUKS specification. Thus, images formatted by RBD can be loaded using external
LUKS-supporting tools such as dm-crypt or QEMU. Furthermore, existing LUKS
data, created outside of RBD, can be imported (by copying the raw LUKS data
into the image) and loaded by RBD encryption.

.. note::
   The LUKS formats are supported on Linux-based systems only.

.. note::
   Currently, only AES-128 and AES-256 encryption algorithms are supported.
   Additionally, xts-plain64 is currently the only supported encryption mode.

To use the LUKS format, start by formatting the image:

.. prompt:: bash $

    rbd encryption format [--cipher-alg {aes-128|aes-256}] {image-spec} {luks1|luks2} {passphrase-file}

The encryption format operation generates a LUKS header and writes it to the
beginning of the image. The header is appended with a single keyslot holding a
randomly-generated encryption key, and is protected by the passphrase read from
`passphrase-file`.

.. note::
   In older versions, if the content of `passphrase-file` ended with a newline
   character, it was stripped off.

By default, AES-256 in xts-plain64 mode (which is the current recommended mode,
and the usual default for other tools) will be used. The format operation
allows selecting AES-128 as well.

Passphrases can be added to and removed from the LUKS header with:

.. prompt:: bash $

    rbd encryption keyslot add [--keyslot {n}] {image-spec} {volume-key-file} {passphrase-file}
    rbd encryption keyslot remove --keyslot {n} {image-spec}
    rbd encryption keyslot list {image-spec}

``keyslot add`` stores the volume key from `volume-key-file`, the key the data
is encrypted with as written by ``volume-key get``, in a new keyslot, the first
free one unless ``--keyslot`` is given, protected by the passphrase from
`passphrase-file`, and prints the keyslot number. The new keyslot gets the key
derivation settings of the lowest keyslot in use, so it costs as much to
unlock. ``--pbkdf``, together with ``--hash``, ``--pbkdf-force-iterations``,
``--pbkdf-memory`` and ``--pbkdf-parallel``, sets them instead, as given.
``keyslot remove`` wipes the given keyslot; the last keyslot bound to the data
cannot be removed. ``keyslot list`` needs no passphrase and prints one row per
keyslot in use, with its key size and key derivation parameters.

Both ``keyslot add`` and ``keyslot remove`` change only the LUKS header. The
encryption key of the data stays the same, so clients that have the image open
are not affected. Each command returns once its changes to the header are
flushed, and nothing is verified afterwards. If a command fails, the header may
have changed in part; ``keyslot list`` shows its state, and the volume key in
hand makes any state repairable with ``keyslot remove`` and ``keyslot add``.

The volume key is read from the header with:

.. prompt:: bash $

    rbd encryption volume-key get {image-spec} {passphrase-file} {volume-key-file}

``volume-key get`` unlocks a keyslot with the passphrase from `passphrase-file`,
writes the volume key to `volume-key-file`, readable by its owner only, and
prints the keyslot it opened. Whoever holds the volume key can read the image
without any passphrase: keep the file as safe as the passphrases and delete it
once the rotation is done.

A copy of the LUKS header, taken before a change, is the way back when a
failed change leaves the header unreadable:

.. prompt:: bash $

    rbd encryption header dump {image-spec} {dump-file}
    rbd encryption header restore {image-spec} {dump-file}

``header dump`` writes the image's original header, byte for byte up to the
data offset, to `dump-file`, readable by its owner only; on a clone only the
RBD clone magic is replaced by the LUKS magic, so that cryptsetup can read the
file. ``header restore`` writes a dump back, whole, with libcryptsetup's own
checks and no others: the dump has to be a valid LUKS header, and while the
image's header still loads, the data offsets have to match; a header that no
longer loads is replaced without conditions. A dump holds every keyslot that
was in use when it was taken, so restoring it brings those passphrases back:
keep it as safe as the passphrases and delete it once the rotation is done.

A passphrase rotation is a sequence of these commands that keeps the image
unlockable at every step, with the volume key in the caller's hands for its
duration: dump the header and keep the dump; read the volume key with the old
passphrase and keep it, wrapped; add the new passphrase to a free keyslot;
prove it, by loading the image with the new passphrase or by listing the
keyslots; record the new passphrase in the key store; remove the keyslot that
holds the old passphrase; list the keyslots; delete the dump and the key. Each
command writes the changed 4 KiB ranges of the header one at a time in
ascending offset order, each acknowledged before the next is issued, flushes
once at the end, and verifies nothing afterwards. The acknowledgement may come
from a cache, so only the flush makes the writes durable, and a crash or an
error before it can leave a partial change, which the volume key makes
repairable: metadata that lists a keyslot whose key material did not land,
shown by ``keyslot list`` and repaired by ``keyslot remove`` and ``keyslot
add``; key material of a keyslot the metadata no longer lists, which is
unusable without the salt and KDF settings that lived in that metadata; or,
when both LUKS2 metadata copies or the LUKS1 header record were hit, a header
that no longer loads, which ``header restore`` brings back. Nothing serializes
concurrent changes to the same header, so a client that rotates from more than
one place has to serialize them itself.

.. note::
   The LUKS header is stored in the image data, so a snapshot taken before a
   rotation keeps the old keyslots. The old passphrase still unlocks it, and
   rolling back to it restores the old keyslots in the image. A clone that is
   formatted with its own encryption needs the passphrase of its parent
   snapshot until it is flattened.

The same header changes can also be applied to the raw data of an image that
is not a clone, using compatible tools such as cryptsetup.

The LUKS header size can vary (up to 136MiB in LUKS2), but is usually up to
16MiB, depending on the version of `libcryptsetup` installed. For optimal
performance, the encryption format will set the data offset to be aligned with
the image stripe period size. For example, expect a minimum overhead of 8MiB if
using an image configured with an 8MiB object size and a minimum overhead of
12MiB if using an image configured with a 4MiB object size and `stripe count`_
of 3.

In LUKS1, sectors, which are the minimal encryption units, are fixed at 512
bytes. LUKS2 supports larger sectors, and for better performance we set
the default sector size to the maximum of 4KiB. Writes which are either smaller
than a sector, or are not aligned to a sector start, will trigger a guarded
read-modify-write chain on the client, with a considerable latency penalty.
A batch of such unaligned writes can lead to I/O races which will further
deteriorate performance. Thus it is advisable to avoid using RBD encryption
in cases where incoming writes cannot be guaranteed to be sector-aligned.

To map a LUKS-formatted image run:

.. prompt:: bash #

    rbd device map -t nbd -o encryption-passphrase-file={passphrase-file} {image-spec}

Note that for security reasons, both the encryption format and encryption load
operations are CPU-intensive, and may take a few seconds to complete. For the
encryption operations of actual image I/O, assuming AES-NI is enabled,
a relative small microseconds latency should be added, as well as a small
increase in CPU utilization.

Examples
========

Create a LUKS2-formatted image with the effective size of 50GiB:

.. prompt:: bash $

    rbd create --size 50G mypool/myimage
    rbd encryption format mypool/myimage luks2 passphrase.bin
    rbd resize --size 50G --encryption-passphrase-file passphrase.bin mypool/myimage

``rbd resize`` command at the end grows the image to compensate for the
overhead associated with the LUKS2 header.

Given a LUKS2-formatted image, create a LUKS2-formatted clone with the
same effective size:

.. prompt:: bash $

    rbd snap create mypool/myimage@snap
    rbd snap protect mypool/myimage@snap
    rbd clone mypool/myimage@snap mypool/myclone
    rbd encryption format mypool/myclone luks2 clone-passphrase.bin

Given a LUKS2-formatted image with the effective size of 50GiB, create
a LUKS1-formatted clone with the same effective size:

.. prompt:: bash $

    rbd snap create mypool/myimage@snap
    rbd snap protect mypool/myimage@snap
    rbd clone mypool/myimage@snap mypool/myclone
    rbd encryption format mypool/myclone luks1 clone-passphrase.bin
    rbd resize --size 50G --allow-shrink --encryption-passphrase-file clone-passphrase.bin --encryption-passphrase-file passphrase.bin mypool/myclone

Since LUKS1 header is usually smaller than LUKS2 header, ``rbd resize``
command at the end shrinks the cloned image to get rid of unneeded
space allowance.

Given a LUKS1-formatted image with the effective size of 50GiB, create
a LUKS2-formatted clone with the same effective size:

.. prompt:: bash $

    rbd resize --size 51G mypool/myimage
    rbd snap create mypool/myimage@snap
    rbd snap protect mypool/myimage@snap
    rbd clone mypool/myimage@snap mypool/myclone
    rbd encryption format mypool/myclone luks2 clone-passphrase.bin
    rbd resize --size 50G --allow-shrink --encryption-passphrase-file passphrase.bin mypool/myimage
    rbd resize --size 50G --allow-shrink --encryption-passphrase-file clone-passphrase.bin --encryption-passphrase-file passphrase.bin mypool/myclone

Since LUKS2 header is usually bigger than LUKS1 header, ``rbd resize``
command at the beginning temporarily grows the parent image to reserve
some extra space in the parent snapshot and consequently the cloned
image. This is necessary to make all parent data accessible in the
cloned image. ``rbd resize`` commands at the end shrink the parent
image back to its original size (this does not impact the parent
snapshot) and also the cloned image to get rid of unused reserved
space.

The same applies to creating a formatted clone of an unformatted
(plaintext) image since an unformatted image does not have a header at
all.

To map a formatted clone, provide encryption formats and passphrases
for the clone itself and all of its explicitly formatted parent images.
The order in which ``encryption-format`` and ``encryption-passphrase-file``
options should be provided is based on the image hierarchy: start with
that of the cloned image, then its parent and so on.

Here is an example of a command that maps a formatted clone:

.. prompt:: bash #

   rbd device map -t nbd -o encryption-passphrase-file=clone-passphrase.bin,encryption-passphrase-file=passphrase.bin mypool/myclone

Rotate the passphrase of a LUKS-formatted image whose only keyslot is 0:

.. prompt:: bash $

    rbd encryption header dump mypool/myimage header.bin
    rbd encryption volume-key get mypool/myimage passphrase.bin volume-key.bin
    rbd encryption keyslot add --keyslot 1 mypool/myimage volume-key.bin new-passphrase.bin
    rbd encryption keyslot list mypool/myimage
    rbd encryption keyslot remove --keyslot 0 mypool/myimage
    rbd encryption keyslot list mypool/myimage

Record `new-passphrase.bin` in the key store before ``keyslot remove``, and
keep `header.bin` and `volume-key.bin` until the rotation is done: with them
any interruption is repaired with ``keyslot remove`` and ``keyslot add``, or
with ``header restore``. Then delete both files: the dump brings the old
passphrase back when restored, and the key opens the image without any.

.. _journal feature: ../rbd-mirroring/#enable-image-journaling-feature
.. _Supported Formats: #supported-formats
.. _rbd-nbd: ../../man/8/rbd-nbd
.. _stripe count: ../../man/8/rbd/#striping
