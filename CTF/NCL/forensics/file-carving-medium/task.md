The security team has found a rather strange file exiting the network, we're not sure if it's containing any sensitive information. Help us identify what's in it.

10:18:20 am

|   |   |
|---|---|
|Q1 - 10 points<br><br>This file initially looks like something green, what's the file format of this green file?||
|Q2 - 25 points<br><br>How many files can be extracted from the binary blob?||
|Q3 - 50 points<br><br>What is the hidden flag in the file?|

---
## Initial Recon

Tried opening the file, only opened a green PNG image.

I assume that the flag is now going to be embedded within this image, so I ran it against stegray. 

Stegray is just a program I made that runs a target file against the popular forensics/metadata/steg tools, such as exiftool, stegseek, binwalk, strings, etc.

I found that binwalk was able to extract a couple files. One of them was flag.txt, which is where I was able to get the SKY flag.