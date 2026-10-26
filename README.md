# WhitePhosphorus 7.27 

Notes on legitimate release?

These positive indicators make me think it is likely to be real and ok:

The whl (wheel) files are zip archives use by python these are legit and the same binary same
files can be found here https://www.lfd.uci.edu/~gohlke/pythonlibs/
https://download.lfd.uci.edu/pythonlibs/archived/cp27/pycurl-7.43.0.3-cp27-cp27m-win32.whl
https://download.lfd.uci.edu/pythonlibs/archived/cp27/pygame-1.9.6-cp27-cp27m-win32.whl

The pyc files are compiled python and I filtered them from my comparison - I suggest you delete
them all.  In fact, nevermind I am deleting them all before packing this for re-release.
Since pyc is just compiled/cached form of the .py file this shouldn't matter and your system
will make your own cache the first time you run this.  I deleted these because checking that
many binaries for backdoors is not reasonable.

I looked at all the source code and it looks good.

That leaves only the two exe files called exploit_x64.exe - I suspect they are a legit part of
the program but analyzing these properly is beyond the scope of what I can do - they could
be backdoored in subtle ways and set to only trigger after a certain date and only in certain
language or timezone by system settings, or who knows - I can't vouch for them. Just saying, I
did my best to look through this but since I don't have the original release and can only
compare with 7.26 previous leak, my verdict is that it's real, and it's probably straight.
That said, only run this in a vm and if you get owned, I'll bet it was one of those exe's.
Oh well!

Oh also there was a small typo fixed in a White Phosphorus module, and there were some other
weird small sabotage that I fixed, like there was a variable that had an extra single
quote like xyz="asdfasdf" instead it was xyz'="asdfasdf", weird stuff like that it all
I fixed.  Oh I also added the Windows dependencies exe from the 7.26 leak.

Lastly, I changed the phone-home version check:

  #set to no if you don't want to callback to Immunity to check
  #the version you are running against the current version
  VersionCheck = no

enjoy!
