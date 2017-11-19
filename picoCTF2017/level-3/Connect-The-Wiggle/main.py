import sqlite3

conn = sqlite3.connect('wigle')
c = conn.cursor()
# c.execute('SELECT * FROM sqlite_master')
# print(c.fetchall())
c.execute('SELECT lat, lon FROM location')
locs = c.fetchall()

with open('data','w') as f:
    for loc in locs:
        f.write('{0},{1}\n'.format(loc[0], loc[1]))

# then use websites to do the drawing thing, do not use python :)
# e.g. http://www.hamstermap.com/quickmap.php
