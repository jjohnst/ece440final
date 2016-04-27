# ece440final
ECE 440 Final Project - Rollcall

*Must have MySQL install on machine.

How to compile:
  1. Download all the files and put them in one location. 
  2. In a terminal, change directory to where you saved the files.
  3. Type "make" without the quotes. This will compile the rollcall and submit files. This should work if you're on a Mac. Some configuration of the libraries to include may be needed. They are declared at the top of the makefile.
  
How to run:
./rollcall requires sudo privileges and takes a command line argument. Typying ./rollcall -h will display the different options. A sample command to run rollcall is "sudo ./rollcall -f". To run the submit program, simply type ./submit.

The file might need to be configured depending on the database. The variables to configure are in the header file. 




Basic GitHub Commands:
1) git clone "path to project location"

2) git config user.email youremail@clemson.edu
      -Always do this after cloning 
      
3) git config user.name "Your name" 
      -Always do this after cloning 
      
4) git add "file you're adding" 
      -Must add before you commit 
      
5) git commit –m "Descriptive commit message"
      -Saves changes to local
      
6) git fetch
      -Makes local aware of changes on the server
      
7) git push
      -Saves changes to cloud *Use "-u" flag for tracking and then "origin" and "master"
      
*) git pull
      -Pulls the most updated file from the server and merges them *This can cause merge conflicts which must be resolved manually 
      
*Always pull before you push
