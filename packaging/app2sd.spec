Name:       app2sd
Summary:    Application installation on external memory
Version:    0.5.22
Release:    1
Group:      Application Framework/Application Installer
License:    Apache-2.0
Source0:    %{name}-%{version}.tar.gz
Source1001: app2sd.manifest

BuildRequires:  pkgconfig(libssl)
BuildRequires:  pkgconfig(vconf)
BuildRequires:  pkgconfig(dlog)
BuildRequires:  pkgconfig(openssl)
BuildRequires:  pkgconfig(db-util)
BuildRequires:  pkgconfig(pkgmgr-info)
BuildRequires:  cmake

%description
Tizen application installation on external memory

%package devel
Summary:    Application install on external memory (devel)
Requires:   app2sd = %{version}-%{release}

%description devel
Tizen application installation on external memory (devel)

%prep
%setup -q
cp %{SOURCE1001} .

%build
%cmake .

make %{?jobs:-j%jobs}

%install
%make_install

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%files
%manifest %{name}.manifest
%defattr(-,root,root,-)
%{_libdir}/libapp2ext.so.*
%{_libdir}/libapp2sd.so.*


%files devel
%manifest %{name}.manifest
%defattr(-,root,root,-)
%{_includedir}/app2ext_interface.h
%{_libdir}/pkgconfig/app2sd.pc
%{_libdir}/libapp2sd.so
%{_libdir}/libapp2ext.so



