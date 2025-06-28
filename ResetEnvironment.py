# Read in the file
with open('settings.toml', 'r') as file:
  filedata = file.read()

# Replace the target string
filedata = filedata.replace('production', 'development')

# Write the file out again
with open('settings.toml', 'w') as file:
  file.write(filedata)