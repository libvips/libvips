---
title: nip4 January progress
---

nip4 is pretty much done! It now loads the two largest workspaces I have
correctly. I'll do a bit more polishing and aim for an alpha release with
pre-compiled binaries for flatpak and Windows by the end of February.

Here's the per-voxel Patlak workspace I made for analyzing pulmonary FDG-PET
scans:

![FDG-PET workspace](/assets/images/nip4-jan-1.png)

The **About nip4** menu item shows some stats:

![Workspace stats](/assets/images/nip4-jan-2.png)

So this workspace has:

- 8,400 rows
- 15,000 images
- over 100 GB of image data
- 8,300 active operations
- looking at `top`, it's running in about 2.5 GB of ram

Here's the [Charisma
workspace](https://www.academia.edu/7276130/J_Dyer_G_Verri_and_J_Cupitt_Multispectral_Imaging_in_Reflectance_and_Photo_induced_Luminescence_modes_a_User_Manual_European_CHARISMA_Project):

![Charisma workspace](/assets/images/nip4-jan-3.png)

This thing is for museum imaging: you give it images taken under visible,
infrared, and UV light with various filters and it aligns them and computes
a range of useful derivatives, such as Kubelka–Munk-modelled UV-induced
visible fluorescence with stray visible light removal.

Looking at **About nip4** for this one, it's only 300 rows, but has
14,000 images and over 120 GB of image data. It runs in about 1.2 GB of ram,
according to `top`.

## Other additions

I've implemented some other features:

### Recover after crash

nip4 saves your work after every change, and keeps the last 10 saves from
each workspace. These save files are normally deleted automatically on exit,
but if there's a crash (sadly inevitable in alpha software) they'll still
be there when it restarts. Click on **Recover after crash** and you get
this window:

![Recover after crash](/assets/images/nip4-jan-4.png)

You can see the saves from each nip4 workspace and select one to recover it.
The **Delete all backups** button wipes the temp area if it's getting too big.

### Drag-drop and copy-paste

You can now drag-drop and copy-paste images and workspaces from your desktop
and file manager. This is very handy for things like screen snapshots. You can
even set nip4 as the image handler for your desktop (!!!).

### Workspace definitions

Each tab in each workspace can have private definitions. Right click on the
workspace background and select **Workspace definitions** and a panel opens on
the right with all the local definitions. You can edit them and press the
**Play** button to process your changes and update everything.

![Workspace definitions](/assets/images/nip4-jan-5.png)

### Edit toolkits

Right-click on the workspace background, pick **Edit toolkits** and you get
the programming window:

![Programming window](/assets/images/nip4-jan-6.png)

You can edit and compile any of the built-in toolkits, though it's a bit
barebones for now. 

### Stop offscreen image renders

nip4 now tracks which thumbnails are visible and starts and stops rendering as
you move around a workspace. This saves a lot of memory and CPU!
