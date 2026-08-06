# ChoreApp F-Droid Repository

This repository hosts an [F-Droid](https://f-droid.org/) repository for
[ChoreApp](https://github.com/Ahzed11/chore-app), a self-hosted household
chore coordinator for Android. The repository is updated automatically by
GitHub Actions: every time a new release is published to the ChoreApp repo,
this repo's index is rebuilt within a few hours, so your F-Droid client picks
up the update without any manual reinstallation.

### Apps

<!-- This table is auto-generated. Do not edit -->
| Icon | Name | Description | Version |
| --- | --- | --- | --- |
<!-- end apps table -->

### How to use
1. At first, you should [install the F-Droid app](https://f-droid.org/), it's an alternative app store for Android.
2. Now you can add this repository to your F-Droid client (Settings → Repositories → `+`):

    ```
    https://raw.githubusercontent.com/Ahzed11/chore-app-fdroid/main/fdroid/repo?fingerprint=2F197F32A3F10720DCEB884640306EA6309E688839BF4AE8E97F056CA2D83F7F
    ```

    Alternatively, you can also scan this QR code:

    <p align="center">
      <img src=".github/qrcode.png?raw=true" alt="F-Droid repo QR code"/>
    </p>

3. Open the link in F-Droid. It will ask you to add the repository. Everything should already be filled in correctly, so just press "OK".
4. You can now install ChoreApp and you will receive updates automatically.

### How updates work
1. A change is merged to `main` in [Ahzed11/chore-app](https://github.com/Ahzed11/chore-app) with a bumped version in `pubspec.yaml`.
2. GitHub Actions builds a signed release APK and publishes it as a GitHub Release.
3. The scheduled workflow in this repo (daily at 02:45 UTC, plus on push/manual dispatch) downloads the new APK, runs `fdroid update`, and commits the fresh index.
4. Your F-Droid client checks this repo's index and shows the update.

### For developers
If you are a developer and want to publish your own apps right from GitHub Actions as an F-Droid repo, the original template is
[xarantolus/fdroid](https://github.com/xarantolus/fdroid) — see [the documentation](setup.md) for more information on how to set it up.

### [License](LICENSE)
The license is for the files in this repository, *except* those in the `fdroid` directory. These files *might* be licensed differently; you can use an F-Droid client to get the details for each app.
