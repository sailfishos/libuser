Name:       libuser
Summary:    A user and group account administration library
Version:    0.64
Release:    1
License:    LGPLv2+
URL:        https://github.com/sailfishos/libuser
Source0:    https://pagure.io/libuser/%{name}-%{version}.tar.gz
Patch0001:  0001-Disable-docs-a-bit-more.patch
Requires(post): /sbin/ldconfig
Requires(postun): /sbin/ldconfig
BuildRequires:  pkgconfig(glib-2.0)
BuildRequires:  pkgconfig(popt)
BuildRequires:  pkgconfig(libcrypt)
BuildRequires:  pam-devel
BuildRequires:  gettext-devel
BuildRequires:  bison

%description
%{summary}.

%package devel
Summary:    Files needed for developing applications which use libuser
Requires:   %{name} = %{version}-%{release}

%description devel
%{summary}.

%package doc
Summary:   Documentation for %{name}
Requires:  %{name} = %{version}-%{release}

%description doc
Man pages for %{name}.

%prep
%autosetup -p1 -n %{name}-%{version}/%{name}

%build
%reconfigure --disable-static \
    --without-python \
    --disable-gtk-doc

%make_build

%install
%make_install

%find_lang libuser

mkdir -p %{buildroot}%{_docdir}/%{name}-%{version}
install -m0644 -t %{buildroot}%{_docdir}/%{name}-%{version} \
	AUTHORS NEWS README TODO

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%files -f libuser.lang
%license COPYING
%config %{_sysconfdir}/libuser.conf
%attr(0755,root,root) %{_bindir}/*
%{_libdir}/*.so.*
%dir %{_libdir}/%{name}
%{_libdir}/%{name}/*.so
%attr(0755,root,root) %{_sbindir}/*

%files devel
%{_includedir}/libuser
%{_libdir}/*.so
%{_libdir}/pkgconfig/*

%files doc
%{_mandir}/man1/*
%{_docdir}/%{name}-%{version}
