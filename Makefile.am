AUTOMAKE_OPIONS=foreign no-dependencies subdir-objects
ACLOCAL_AMFLAGS = -I m4
SUBDIRS = src

#INCLUDES = @INCLUDES@

install-data-local:
	test -z "$(DESTDIR)$(sysconfdir)" || /bin/mkdir -p "$(DESTDIR)$(sysconfdir)"
	test -f "$(DESTDIR)$(sysconfdir)/jae.yaml" || $(INSTALL_DATA) etc/jae.yaml "$(DESTDIR)$(sysconfdir)/jae.yaml"
	test -z "$(DESTDIR)$(bindir)" || /bin/mkdir -p "$(DESTDIR)$(bindir)"
	$(INSTALL) -d "$(DESTDIR)$(mandir)/man8"
	$(INSTALL) -m 644 etc/jae.8 "$(DESTDIR)$(mandir)/man8"
	$(INSTALL) -m 755 src/jae "$(DESTDIR)$(bindir)/jae"
	$(INSTALL) -d "$(DESTDIR)/var/log/jae"
	$(INSTALL) -d "$(DESTDIR)/var/run/jae"
	@echo ""
	@echo "------------------------------------------------------------------------------"
	@echo "JAE has been installed! You still need to do a few more things before your"
	@echo "up and running.  For more information, see https://XXXXX.readthedocs.io"
	@echo "------------------------------------------------------------------------------"
	@echo ""


