Name:       app2sd
Summary:    Application installation on external memory
Version:    0.5.24
Release:    1
Group:      Application Framework/Application Installer
License:    Apache-2.0
Source0:    %{name}-%{version}.tar.gz

BuildRequires:  cmake
BuildRequires:  pkgconfig(db-util)
BuildRequires:  pkgconfig(dlog)
BuildRequires:  pkgconfig(libssl)
BuildRequires:  pkgconfig(openssl)
BuildRequires:  pkgconfig(pkgmgr-info)
BuildRequires:  pkgconfig(vconf)

%description
Tizen application installation on external memory

%package devel
Summary:        Application install on external memory (devel)
Requires:       app2sd = %{version}-%{release}

%description devel
Tizen application installation on external memory (devel)

%prep
%setup -q
cp %{SOURCE1001} .

%build
%cmake .
make %{?_smp_mflags}

%install
%make_install

mkdir -p %{buildroot}/usr/share/license
cp LICENSE %{buildroot}/usr/share/license/%{name}

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%files
%manifest %{name}.manifest
%defattr(-,root,root,-)
%{_libdir}/libapp2ext.so.*
%{_libdir}/libapp2sd.so*
/usr/share/license/%{name}

%files devel
%manifest %{name}.manifest
%defattr(-,root,root,-)
%{_includedir}/app2ext_interface.h
%{_libdir}/pkgconfig/app2sd.pc
%{_libdir}/libapp2sd.so
%{_libdir}/libapp2ext.so



