pkgname="ptunnel-ng"
pkgver=1.42
pkgrel=1
pkgdesc="A TCP forwarder and proxy used for ICMP/UDP tunneling without creating tun devices. (Ping Tunnel, ICMP Echo Tunnel, UDP Tunnel)"
arch=('i686' 'x86_64')
url='https://www.github.com/lnslbrty/ptunnel-ng'
license=('BSD-3')
makedepends=('git')
provides=("ptunnel-ng=${pkgver}")
source=("https://github.com/lnslbrty/ptunnel-ng/archive/v${pkgver}.tar.gz")
md5sums=('b7741527a7833bc06130ea67502ae21a')

build() {
	cd "${srcdir}/${pkgname}-${pkgver}"
	./configure \
		--prefix=/usr \
		--libdir=/usr/lib \
		--disable-pcap \
		--disable-selinux
	make
}

package() {
	cd "${srcdir}/${pkgname}-${pkgver}"
	make DESTDIR="${pkgdir}" install
	find "${pkgdir}" -type d -name .git -exec rm -r '{}' +
	install -D -m644 COPYING "${pkgdir}/usr/share/licenses/ptunnel-ng/LICENSE"
}
