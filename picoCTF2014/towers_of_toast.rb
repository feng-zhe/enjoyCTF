#!/usr/local/bin/ruby -w

def isPrime(n)
    for i in (2..n-1) do
        if n%i == 0 then
            return false
        end
    end
    return true
end

def getPrimes(size)
    res = Array.new
    curr = 2
    while res.length<size do
        if isPrime(curr) then
            res.push(curr)
        end
        curr += 1
    end
    return res
end

primes = getPrimes(40)
res = 1
primes.each do |p|
    res *= p
end
puts res
