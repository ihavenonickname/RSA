require 'openssl'

class RSAKey
    def initialize(exponent, mod)
        @exponent = exponent
        @mod = mod
    end

    def encrypt(value)
        value.to_bn().mod_exp(@exponent, @mod)
    end
end

def modinv(u, v)
    u1 = 1
    u3 = u
    v1 = 0
    v3 = v

    counter = 1

    while v3 != 0 do
        q = u3 / v3
        t3 = u3 % v3
        t1 = u1 + q * v1

        u1 = v1
        v1 = t1
        u3 = v3
        v3 = t3

        counter = counter.next()
    end

    if u3 != 1 then
        0
    elsif counter.even? then
        v - u1
    else
        u1
    end
end

def generate_rsa_keys(p, q)
    phi = (p - 1) * (q - 1)

    n = p * q
    e = 65537
    d = modinv(e, phi)

    public_key = RSAKey.new(e, n)
    private_key = RSAKey.new(d, n)

    [public_key, private_key]
end

public_key, private_key = generate_rsa_keys(23, 29)

original_value = 42

encripted = public_key.encrypt(original_value)
decripted = private_key.encrypt(encripted)

puts "#{original_value} #{encripted} #{decripted}"
