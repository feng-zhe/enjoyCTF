Reading the source code, looks like this may has something to do with the `union` in a C struct.

Yep. Just use the union and write the string field so that it will later be read as the expected integer.
