# Codatify

## Fixup Code 
Define all undefined data in the .text section as code and covert it to a 
function if applicable.

### Before

![Code Before](./img/before_code.png)

### After

![Code After](./img/after_code.png)

## Fixup Data
Define uninitialized strings and pointers in the code. All other uninitialized
data is converted to a DWORD. Finally, search for function tables and rename
functions based off the discovered tables.

### Before 

**Data Section**

![Data Before](./img/before_data.png)

**Cross Reference**

![Xref Before](./img/before_xref.png)

### After

**Data Section**

![Data After](./img/after_data.png)

**Cross Reference**

![Xref Before](./img/after_xref.png)
