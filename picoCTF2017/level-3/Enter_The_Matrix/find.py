import math
# try 10*10 most
MAX_ROWS = 10
MAX_COLS = 10

for row in range(1, MAX_ROWS+1):
    for col in range(1, MAX_COLS+1):
        to_skip = int(math.ceil(row*col/4.0)*4)    # the number of float to be skipped
        # try whether we can shoot the next matrix struct's data pointer
        for x in range(0, row):
            for y in range(0, col):
                if x*row+y == to_skip+2:    # to_skip+2 is the place where data pointer is
                    print("row: {}, col: {}, shoot it by: set #id {} {}".format(row, col, x, y))

print('End');
