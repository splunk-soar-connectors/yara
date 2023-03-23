**Initial Release**

- Initial release of application supports downloading Yara rules with `update yara sources`, listing those files with `list yara sources`, clearing them from disk with `clear yara sources` and scanning with them with `yara scan`.
- `update yara sources` expects an asset with Environment variables defined to be a source for downloading one or more files and a value of the URL to download, something that *requests must support*.
- `list yara sources` will list the application's state directory, by default, and if specified, limit that search to a directory in the app's state directory.  This allows listing sets of malware rules that may all belong to an asset.
- `clear yara sources` will clear all non-state.json files from the app's state directory.
- `yara scan` will compile any downloaded rules, cache them for use later and load any cache before recompiling.  It has boolean parameters for supporting include directives and fast mode.  It allows specifying a scan directory or a vault ID.  Also optionally, specify stack size, max strings per rule, timeout and max match data values to configure how Yara works at runtime.