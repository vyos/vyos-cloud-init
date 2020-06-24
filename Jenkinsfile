// Copyright (C) 2020 VyOS maintainers and contributors
//
// This program is free software; you can redistribute it and/or modify
// in order to easy exprort images built to "external" world
// it under the terms of the GNU General Public License version 2 or later as
// published by the Free Software Foundation.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

@NonCPS

// Using a version specifier library, use 'current' branch. The underscore (_)
// is not a typo! You need this underscore if the line immediately after the
// @Library annotation is not an import statement!
@Library('vyos-build@current')_

// Start package build using library function from https://github.com/c-po/vyos-build
def buildCmd = "./packages/bddeb && mv *.deb .."
buildPackage(null, null, buildCmd)
