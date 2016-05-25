Name:           privacy-guard-server
Version:        0.0.1
Release:        1
License:        Apache-2.0
Summary:        Privacy Management
Group:          Security/Libraries
Source0:        %{name}-%{version}.tar.gz
Source1:        privacy-guard-server.service
Source2: 		privacy-guard-server.socket
Source1001:     privacy-guard-server.manifest
Source1002:     privacy-guard-server-devel.manifest
Source1003:     privacy-guard-client.manifest
Source1004:     privacy-guard-client-devel.manifest
BuildRequires:  cmake
BuildRequires:  gettext-tools
BuildRequires:  pkgconfig(capi-base-common)
BuildRequires:  pkgconfig(db-util)
BuildRequires:  pkgconfig(dbus-1)
BuildRequires:  pkgconfig(dbus-glib-1)
BuildRequires:  pkgconfig(dlog)
BuildRequires:  pkgconfig(glib-2.0)
BuildRequires:  pkgconfig(libxml-2.0)
BuildRequires:  pkgconfig(pkgmgr-info)
BuildRequires:  pkgconfig(sqlite3)
BuildRequires:	pkgconfig(capi-system-info)
BuildRequires:	pkgconfig(libtzplatform-config)
BuildRequires:	pkgconfig(security-privilege-manager)
BuildRequires:	pkgconfig(cynara-monitor)

Requires(post):   /sbin/ldconfig
Requires(postun): /sbin/ldconfig

%description
Privacy Management

%package -n privacy-guard-server-devel
Summary:        Privacy Guard Server
Requires:       privacy-guard-server = %{version}

%description -n privacy-guard-server-devel
privacy-guard server devel

%package -n privacy-guard-client
Summary:        Privacy Guard client
Requires:       privacy-guard-server = %{version}

%description -n privacy-guard-client
privacy-guard client

%package -n privacy-guard-client-devel
Summary:        Privacy Guard client devel
Requires:       privacy-guard-client = %{version}

%description -n privacy-guard-client-devel
Privacy Management(development files)


%prep
%setup -q
cp %{SOURCE1001} .
cp %{SOURCE1002} .
cp %{SOURCE1003} .
cp %{SOURCE1004} .

%build
%{!?build_type:%define build_type "Release"}
%cmake . -DPREFIX=%{_prefix} \
        -DEXEC_PREFIX=%{_exec_prefix} \
        -DLIBDIR=%{_libdir} \
        -DINCLUDEDIR=%{_includedir} \
        -DCMAKE_BUILD_TYPE=%{build_type} \
        -DVERSION=%{version} \
        -DFILTER_LISTED_PKG=ON \
        -DPRIVACY_POPUP=OFF
make %{?_smp_mflags}

%install
mkdir -p %{buildroot}%{_prefix}/bin
cp res/usr/bin/* %{buildroot}%{_bindir}/
mkdir -p %{buildroot}%{TZ_SYS_DB}

%make_install
mkdir -p %{buildroot}%{_libdir}/systemd/system/multi-user.target.wants
install -m 0644 %{SOURCE1} %{buildroot}%{_libdir}/systemd/system/privacy-guard-server.service
ln -sf /usr/lib/systemd/system/privacy-guard-server.service %{buildroot}%{_libdir}/systemd/system/multi-user.target.wants/privacy-guard-server.service
mkdir -p %{buildroot}%{_libdir}/systemd/system/socket.target.wants
install -m 0644 %{SOURCE2} %{buildroot}%{_libdir}/systemd/system/privacy-guard-server.socket
ln -sf /usr/lib/systemd/system/privacy-guard-server.socket %{buildroot}%{_libdir}/systemd/system/socket.target.wants/privacy-guard-server.socket

%post -n privacy-guard-server
/sbin/ldconfig

echo "Check privacy guard DB"
if [ ! -f %{TZ_SYS_DB}/.privacy_guard.db ]
then
	echo "Create privacy guard DB"
	%{_bindir}/privacy_guard_create_clean_db.sh
fi
chsmack -a System %{TZ_SYS_DB}/.privacy_guard.db
chsmack -a System %{TZ_SYS_DB}/.privacy_guard.db-journal

%postun -p /sbin/ldconfig

%post -n privacy-guard-client -p /sbin/ldconfig
%postun -n privacy-guard-client -p /sbin/ldconfig

/usr/sbin/setcap cap_chown,cap_dac_override,cap_lease+eip /usr/bin/privacy-guard-server


%files -n privacy-guard-server
%defattr(-,root,root,-)
%license  LICENSE.APLv2
%manifest privacy-guard-server.manifest
#%{TZ_SYS_DB}/.privacy_guard_privacylist.db
%{_bindir}/*
%{_libdir}/systemd/system/*


%files -n privacy-guard-server-devel
%{_libdir}/pkgconfig/privacy-guard-server.pc

%files -n privacy-guard-client
%defattr(-,root,root,-)
%license  LICENSE.APLv2
%manifest privacy-guard-client.manifest
%{_libdir}/libprivacy-guard-client.so*
%{_sysconfdir}/package-manager/parserlib/libprivileges.so

%files -n privacy-guard-client-devel
%defattr(-,root,root,-)
%manifest privacy-guard-client-devel.manifest
%{_includedir}/*
%{_libdir}/pkgconfig/privacy-guard-client.pc
