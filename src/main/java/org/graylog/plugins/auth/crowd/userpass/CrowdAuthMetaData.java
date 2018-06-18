/**
*
* Crowd username-password authentication plugin for Graylog
*
* Copyright (C) 2018 University Of Helsinki (The National Library Of Finland)
*
* This file is part of graylog-plugin-auth-crowd-userpass
*
* graylog-plugin-auth-crowd-userpass program is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as
* published by the Free Software Foundation, either version 3 of the
* License, or (at your option) any later version.
*
* graylog-plugin-auth-crowd-userpass is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU eneral Public License
* along with this program.  If not, see <http://www.gnu.org/licenses/>.
*
*/
package org.graylog.plugins.auth.crowd.userpass;

import org.graylog2.plugin.PluginMetaData;
import org.graylog2.plugin.ServerStatus;
import org.graylog2.plugin.Version;

import java.net.URI;
import java.util.Collections;
import java.util.Set;

/**
 * Implement the PluginMetaData interface here.
 */
public class CrowdAuthMetaData implements PluginMetaData {
    private static final String PLUGIN_PROPERTIES = "org.graylog.plugins.graylog-plugin-auth-crowd-userpass/graylog-plugin.properties";

    @Override
    public String getUniqueId() {
        return "org.graylog.plugins.auth.crowd.userpass.CrowdAuthPlugin";
    }

    @Override
    public String getName() {
        return "Crowd Authentication Provider";
    }

    @Override
    public String getAuthor() {
        return "Graylog, Inc";
    }

    @Override
    public URI getURL() {
        return URI.create("https://www.graylog.org/");
    }

    @Override
    public Version getVersion() {
        return Version.fromPluginProperties(this.getClass(), PLUGIN_PROPERTIES, "version", Version.from(0, 0, 0, "unknown"));
    }

    @Override
    public String getDescription() {
        return "Crowd Authentication provider";
    }

    @Override
    public Version getRequiredVersion() {
        return Version.fromPluginProperties(this.getClass(), PLUGIN_PROPERTIES, "graylog.version", Version.CURRENT_CLASSPATH);
    }

    @Override
    public Set<ServerStatus.Capability> getRequiredCapabilities() {
        return Collections.emptySet();
    }
}
