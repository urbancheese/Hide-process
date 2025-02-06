# hideproc - Linux Kernel Module for Hiding Processes from `/proc`

## Overview

`hideproc` is a Linux kernel module designed to hide a specific process from the `/proc` filesystem. It provides a mechanism to dynamically specify the PID of the process to be hidden through the `/proc/hidden_pid` file. This module hooks into the `readdir` and `lookup` functions of the `/proc` filesystem, making the specified process invisible to standard tools like `ps`, `top`, or `ls /proc`.

**Important**: This module should only be used for ethical and educational purposes. Hiding processes from `/proc` could be used maliciously and is not recommended in production environments without proper monitoring.

## Features

- Hides a process from `/proc` based on its PID.
- Dynamically configurable through the `/proc/hidden_pid` file.
- Hooks the `readdir` and `lookup` functions of the `/proc` filesystem.
- Thread-safe with the use of a mutex to protect critical operations.
- Graceful cleanup of the original `file_operations` on module removal.
