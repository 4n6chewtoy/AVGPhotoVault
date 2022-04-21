# AVGPhotoVault
A python script to decrypt media files encrypted using the Android application 'AVG Antivirus'. Will identify PIN / pattern used. (https://play.google.com/store/apps/details?id=com.antivirus&hl=en_GB&gl=US). Original Blog Post: https://theincidentalchewtoy.wordpress.com/2022/02/23/decrypting-the-avg-photo-vault/.

AVG primarily known as an Antivirus solution bundles together some other useful features to '_Keep your personal data safe with App Lock_' and Photo Vault. Photovault is a free feature within AVG for Android but is limited to 10 items, the upgraded version will provide less limitations.

## Script Usage

The script takes certain arguments but it important to note that there is a requirement for the file **PasscodeWithValues.txt** to be present in the same location of the script otherwise decryption will not be possible.

Script takes 3 arguments:

1. Data folder (/data/data/com.antivirus)
2. Encrypted media folder (/sdcard/Vault/)
3. Output folder

The script is designed to identify any PIN and / or pattern lock from within relevant files. It will then decrypt any user encrypted files and output them with a 'best guess' file extension. It is important to mention that if the '/data/data/' folder is not present that the encrypted files can still be decrypted providing the key file file is present within the **.key_store** file.

There are minimal checks in place for the script to work so please take that into account!

Any questions, or issues let me know https://twitter.com/4n6chewtoy
