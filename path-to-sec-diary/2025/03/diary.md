# 2025-03-01

Samefully I didn't do anything yesterday.

Today, I worked on the "Sacred Scrolls: Revenge". Haven't found anything
interesting yet. Only a 7-byte overflow thing. Now sure how we will use it to
read the flag.

Will see how it goes tomorrow.

# 2025-03-02, 2025-03-03

Struggling with the "very easy" challenge "Sacred Scrolls: Revenge". Looks like
I forgot all things about the ret2libc. Learned a lot from this challenge.
Unfortunately, the challenge itself has an issue so that I cannot finish it.

Will adjust my goal to finish all the pwn up to the medium difficulty. And then
start to find CVEs among the well-known public softwares. I can do this!

# 2025-03-05

finished the pwn challenge "Entity". Very easy. First-time coding the solver.py
with pwn totally alone.

# 2025-03-07

Finished the Space-pirate-Going-Deeper pwn challenge. Wasted some time trying to
bypass the param123 checks. Then I realized I can jump to the right place by
overwriting one-byte of the return address since the binary has PIE disabled.
