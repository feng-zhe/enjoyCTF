#!/usr/bin/env python3

from googletrans import Translator

translator = Translator()

input_file = "quotes-only-spanish.txt"
output_file = "quotes-only-english.txt"
with open(input_file, "r") as fi:
    with open(output_file, "w") as fw:
        for line in fi.readlines():
            fw.write(translator.translate(line, src="es", dest="en").text + "\n")
