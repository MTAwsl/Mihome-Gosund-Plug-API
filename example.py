from gosund_plug import GosundPlug

example = GosundPlug("192.168.1.233", "ffffffffffffffffffffffffffffffff")

print(example.status()) # Returns a boolean which value is True when it's on and False when it's off

example.on() # Switch on
example.off() # Switch off