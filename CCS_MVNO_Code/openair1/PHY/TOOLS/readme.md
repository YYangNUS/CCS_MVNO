# xForms-based Scope

## How to run and troubleshooting

To compile OAI, build with scope support:
```
./build_oai --build-lib nrscope ...
```

To use the scope, run the xNB or the UE with option `-d`. If you receive the
error
```
In fl_initialize() [flresource.c:995]: 5G-gNB-scope: Can't open display :0
In fl_bgn_form() [forms.c:347]: Missing or failed call of fl_initialize()
```
you can allow root to open X windows:
```
xhost +si:localuser:root
```

### Usage in gdb with Scope enabled

In gdb, when you break, you can refresh immediately the scope view by calling the display function.
The first parameter is the graph context, nevertheless we keep the last value for a dirty call in gdb (so you can use '0')

Example with no variable known
```
phy_scope_nrUE(0, PHY_vars_UE_g[0][0], 0, 0, 0)
```
or
```
phy_scope_gNB(0, phy_vars_gnb, phy_vars_ru, UE_id)
```
