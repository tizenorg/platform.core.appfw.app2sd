Name:       app2sd
Summary:    Application installation on external memory
Version:    0.5.42
Release:    1
Group:      Application Framework/Package Management
License:    Apache-2.0
Source0:    %{name}-%{version}.tar.gz

BuildRequires:  pkgconfig(libssl)
BuildRequires:  pkgconfig(dlog)
BuildRequires:  pkgconfig(openssl)
BuildRequires:  pkgconfig(db-util)
BuildRequires:  pkgconfig(pkgmgr-info)
BuildRequires:  pkgconfig(minizip)
BuildRequires:  pkgconfig(libtzplatform-config)
BuildRequires:  pkgconfig(gio-2.0)
BuildRequires:  pkgconfig(glib-2.0)
BuildRequires:  cmake

%description
Tizen application installation on external memory

%package devel
Summary:    Application install on external memory (devel)
Group:      Development/Libraries
Requires:   app2sd = %{version}-%{release}

%description devel
Tizen application installation on external memory (devel)

%package test
Summary:    Application install on external memory (test)
Group:      Development/Libraries
Requires:   app2sd = %{version}-%{release}

%description test
Tizen application installation on external memory (test)

%prep
%setup -q

%build
%cmake .

make %{?jobs:-j%jobs}

%install
rm -rf %{buildroot}
%make_install

mkdir -p %{buildroot}/usr/share/license
cp LICENSE %{buildroot}/usr/share/license/%{name}

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%files
%manifest app2sd.manifest
%defattr(-,root,root,-)
%{_libdir}/libapp2ext.so.*
%{_libdir}/libapp2sd.so*
%{_bindir}/app2sd-server
%{_datadir}/dbus-1/system-services/org.tizen.app2sd.service
%config %{_sysconfdir}/dbus-1/system.d/org.tizen.app2sd.conf
/usr/share/license/%{name}

%files devel
%defattr(-,root,root,-)
%{_includedir}/app2ext_interface.h
%{_libdir}/pkgconfig/app2sd.pc
%{_libdir}/libapp2sd.so
%{_libdir}/libapp2ext.so

%files test
%defattr(-,root,root,-)
%{_bindir}/test_app2ext

