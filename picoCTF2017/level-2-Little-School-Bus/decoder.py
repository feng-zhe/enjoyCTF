#!/usr/bin/python3

from PIL import Image

def decode(img_path, n = 1):
    """
    this function will try brute force way, the confirm key is 'flag'
    """
    try:
        img = Image.open(img_path)
    except:
        print('cannot open image');
        return

    # pixes = img.load()
    # return [pixes[0,198],pixes[1,198],pixes[2,198]]

    MASK = (1<<n) - 1
    pixes = list(img.getdata())
    for offset in range(8): # the offset is to make sure we will start at all possible place
        for order in [(0,1,2),(0,2,1),(1,2,0),(1,0,2),(2,1,0),(2,0,1)]: # there are 6 possible orders of using the LSB of RGB
            rst = '' # start to construct the result
            binary = ''
            for i in range(offset, len(pixes)):
                pix = pixes[i]
                binary += str(pix[order[0]]&MASK)
                binary += str(pix[order[1]]&MASK)
                binary += str(pix[order[2]]&MASK)
            rst = bin2char(binary)
            if 'flag' in rst:
                return rst

def bin2char(bin_str):
    rst = ''
    for i in range(0,len(bin_str),8):
        rst += chr(int(bin_str[i:i+8],2))
    return rst

def main():
    print(decode('littleschoolbus.bmp'))

if __name__ == '__main__':
    main()
