
PIDGIN_TREE_TOP ?= ../pidgin-2.10.11
PIDGIN3_TREE_TOP ?= ../pidgin-main
LIBPURPLE_DIR ?= $(PIDGIN_TREE_TOP)/libpurple
WIN32_DEV_TOP ?= $(PIDGIN_TREE_TOP)/../win32-dev

WIN32_CC ?= $(WIN32_DEV_TOP)/mingw-4.7.2/bin/gcc

PKG_CONFIG ?= pkg-config
DIR_PERM = 0755
LIB_PERM = 0755
FILE_PERM = 0644
MAKENSIS ?= makensis

CFLAGS	?= -O2 -g -pipe
LDFLAGS ?= 

# Do some nasty OS and purple version detection
ifeq ($(OS),Windows_NT)
  TRILLIANWEB_TARGET = libtrillianweb.dll
  TRILLIANWEB_DEST = "$(PROGRAMFILES)/Pidgin/plugins"
  TRILLIANWEB_ICONS_DEST = "$(PROGRAMFILES)/Pidgin/pixmaps/pidgin/protocols"
  MAKENSIS = "$(PROGRAMFILES)/NSIS/makensis.exe"
else

  UNAME_S := $(shell uname -s)

  #.. There are special flags we need for OSX
  ifeq ($(UNAME_S), Darwin)
    #
    #.. /opt/local/include and subdirs are included here to ensure this compiles
    #   for folks using Macports.  I believe Homebrew uses /usr/local/include
    #   so things should "just work".  You *must* make sure your packages are
    #   all up to date or you will most likely get compilation errors.
    #
    INCLUDES = -I/opt/local/include -lz $(OS)

    CC = gcc
  else
    INCLUDES = 
    CC ?= gcc
  endif

  ifeq ($(shell $(PKG_CONFIG) --exists purple-3 2>/dev/null && echo "true"),)
    ifeq ($(shell $(PKG_CONFIG) --exists purple 2>/dev/null && echo "true"),)
      TRILLIANWEB_TARGET = FAILNOPURPLE
      TRILLIANWEB_DEST =
	  TRILLIANWEB_ICONS_DEST =
	  TRILLIANWEB_THEME_DEST =
    else
      TRILLIANWEB_TARGET = libtrillianweb.so
      TRILLIANWEB_DEST = $(DESTDIR)`$(PKG_CONFIG) --variable=plugindir purple`
	  TRILLIANWEB_ICONS_DEST = $(DESTDIR)`$(PKG_CONFIG) --variable=datadir purple`/pixmaps/pidgin/protocols
    endif
  else
    TRILLIANWEB_TARGET = libtrillianweb3.so
    TRILLIANWEB_DEST = $(DESTDIR)`$(PKG_CONFIG) --variable=plugindir purple-3`
	TRILLIANWEB_ICONS_DEST = $(DESTDIR)`$(PKG_CONFIG) --variable=datadir purple-3`/pixmaps/pidgin/protocols
  endif
endif

WIN32_CFLAGS = -I$(WIN32_DEV_TOP)/glib-2.28.8/include -I$(WIN32_DEV_TOP)/glib-2.28.8/include/glib-2.0 -I$(WIN32_DEV_TOP)/glib-2.28.8/lib/glib-2.0/include -DENABLE_NLS -DPACKAGE_VERSION='"$(PLUGIN_VERSION)"' -Wall -Wextra -Werror -Wno-deprecated-declarations -Wno-unused-parameter -fno-strict-aliasing -Wformat -Wno-sign-compare
WIN32_LDFLAGS = -L$(WIN32_DEV_TOP)/glib-2.28.8/lib -L$(PROTOBUF_C_DIR)/bin -lpurple -lintl -lglib-2.0 -lgobject-2.0 -g -ggdb -static-libgcc -lz
WIN32_PIDGIN2_CFLAGS = -I$(PIDGIN_TREE_TOP)/libpurple -I$(PIDGIN_TREE_TOP) $(WIN32_CFLAGS)
WIN32_PIDGIN3_CFLAGS = -I$(PIDGIN3_TREE_TOP)/libpurple -I$(PIDGIN3_TREE_TOP) -I$(WIN32_DEV_TOP)/gplugin-dev/gplugin $(WIN32_CFLAGS)
WIN32_PIDGIN2_LDFLAGS = -L$(PIDGIN_TREE_TOP)/libpurple $(WIN32_LDFLAGS)
WIN32_PIDGIN3_LDFLAGS = -L$(PIDGIN3_TREE_TOP)/libpurple -L$(WIN32_DEV_TOP)/gplugin-dev/gplugin $(WIN32_LDFLAGS) -lgplugin

C_FILES = \
	libtrillianweb.c 
PURPLE_COMPAT_FILES := purple2compat/http.c purple2compat/purple-socket.c
PURPLE_C_FILES := libtrillianweb.c $(C_FILES)



.PHONY:	all install FAILNOPURPLE clean translations

all: $(TRILLIANWEB_TARGET)

libtrillianweb.so: $(PURPLE_C_FILES) $(PURPLE_COMPAT_FILES)
	$(CC) -fPIC $(CFLAGS) -shared -o $@ $^ $(LDFLAGS) $(PROTOBUF_OPTS) `$(PKG_CONFIG) purple glib-2.0 zlib --libs --cflags`  $(INCLUDES) -Ipurple2compat -g -ggdb

libtrillianweb3.so: $(PURPLE_C_FILES)
	$(CC) -fPIC $(CFLAGS) -shared -o $@ $^ $(LDFLAGS) $(PROTOBUF_OPTS) `$(PKG_CONFIG) purple-3 glib-2.0 zlib --libs --cflags` $(INCLUDES)  -g -ggdb

libtrillianweb.dll: $(PURPLE_C_FILES) $(PURPLE_COMPAT_FILES)
	$(WIN32_CC) -shared -o $@ $^ $(WIN32_PIDGIN2_CFLAGS) $(WIN32_PIDGIN2_LDFLAGS) -Ipurple2compat

libtrillianweb3.dll: $(PURPLE_C_FILES)
	$(WIN32_CC) -shared -o $@ $^ $(WIN32_PIDGIN3_CFLAGS) $(WIN32_PIDGIN3_LDFLAGS)

install: $(TRILLIANWEB_TARGET)
#install-icons install-theme
	mkdir -m $(DIR_PERM) -p $(TRILLIANWEB_DEST)
	install -m $(LIB_PERM) -p $(TRILLIANWEB_TARGET) $(TRILLIANWEB_DEST)

# install-icons: icons/16/skype.png icons/22/skype.png icons/48/skype.png icons/16/skypeout.png icons/22/skypeout.png icons/48/skypeout.png
	# mkdir -m $(DIR_PERM) -p $(TRILLIANWEB_ICONS_DEST)/16
	# mkdir -m $(DIR_PERM) -p $(TRILLIANWEB_ICONS_DEST)/22
	# mkdir -m $(DIR_PERM) -p $(TRILLIANWEB_ICONS_DEST)/48
	# install -m $(FILE_PERM) -p icons/16/skype.png $(TRILLIANWEB_ICONS_DEST)/16/skype.png
	# install -m $(FILE_PERM) -p icons/22/skype.png $(TRILLIANWEB_ICONS_DEST)/22/skype.png
	# install -m $(FILE_PERM) -p icons/48/skype.png $(TRILLIANWEB_ICONS_DEST)/48/skype.png
	# install -m $(FILE_PERM) -p icons/16/skypeout.png $(TRILLIANWEB_ICONS_DEST)/16/skypeout.png
	# install -m $(FILE_PERM) -p icons/22/skypeout.png $(TRILLIANWEB_ICONS_DEST)/22/skypeout.png
	# install -m $(FILE_PERM) -p icons/48/skypeout.png $(TRILLIANWEB_ICONS_DEST)/48/skypeout.png

installer: pidgin-trillianweb.nsi libtrillianweb.dll
	$(MAKENSIS) "/DPIDGIN_VARIANT"="Pidgin" "/DPRODUCT_NAME"="pidgin-trillianweb" "/DINSTALLER_NAME"="pidgin-trillianweb-installer" pidgin-trillianweb.nsi

install-theme: theme
	mkdir -m $(DIR_PERM) -p $(TRILLIANWEB_THEME_DEST)
	install -m $(FILE_PERM) -p theme $(TRILLIANWEB_THEME_DEST)/theme

translations: po/trillianweb.pot

po/trillianweb.pot: 
	xgettext $^ -k_ --no-location -o $@

po/%.po: po/trillianweb.pot
	msgmerge $@ po/trillianweb.pot > tmp-$*
	mv -f tmp-$* $@

po/%.mo: po/%.po
	msgfmt -o $@ $^

%-locale-install: po/%.mo
	install -D -m $(FILE_PERM) -p po/$(*F).mo $(LOCALEDIR)/$(*F)/LC_MESSAGES/purple-trillianweb.mo
	
FAILNOPURPLE:
	echo "You need libpurple development headers installed to be able to compile this plugin"

clean:
	rm -f $(TRILLIANWEB_TARGET)

