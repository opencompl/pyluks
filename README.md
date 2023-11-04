# pyluks

A Python implementation of cryptsetup/luks that makes it possible to turn a
unencrypted file system image into a luks-compatible encrypted filesytem image.

Warning: This tool has not been reviewed for security and might use unsafe defaults.

```
usage: PyLuks [-h] password unencrypted_input_file_image encrypted_output_file_image
PyLuks: error: the following arguments are required: password, unencrypted_input_file_image, encrypted_output_file_image

```
