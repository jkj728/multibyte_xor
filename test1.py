import myModule

# Some test data including NULL character in the middle
mydata = bytearray([65, 0, 66, 67, 68, 69, 70])
print(mydata)

# call module
newdata = myModule.diff_stream(mydata, 3)
newdata = bytearray(newdata)

print(newdata)
