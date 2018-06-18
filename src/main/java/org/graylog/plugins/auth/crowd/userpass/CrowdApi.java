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

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSession;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonArray;
import javax.json.JsonValue;
import javax.json.JsonReader;
import javax.json.JsonBuilderFactory;
import java.net.URL;
import java.util.Base64;
import java.util.Set;
import java.util.Map;
import java.util.HashSet;
import java.util.HashMap;
import java.util.Arrays;

public class CrowdApi {

  private String apiUrl;
  private String appName;
  private String appPassword;
  private boolean verifyCert;

  public CrowdApi(String apiUrl, String appName, String appPassword, boolean verifyCert) {
    this.apiUrl = apiUrl;
    this.appName = appName;
    this.appPassword = appPassword;
    this.verifyCert = verifyCert;
  }

  protected Map<String, String> authenticateUser(String username, String password) throws CrowdApiException, IOException {
    HttpsURLConnection conn = createPostConnection("/usermanagement/1/session");
    JsonObject requestBody = createAuthBody(username, password);

    writeBody(conn.getOutputStream(), requestBody);

    JsonObject responseBody = readBody(conn.getInputStream());

    if (conn.getResponseCode() >= 200 || conn.getResponseCode() < 300) {
      Map<String,String> userDetails = new HashMap<String,String>(4);
      conn.disconnect();
      conn = createGetConnection("/usermanagement/1/user?username="+username);
      responseBody = readBody(conn.getInputStream());
      conn.disconnect();

      userDetails.put("first-name", responseBody.getString("first-name"));
      userDetails.put("last-name", responseBody.getString("last-name"));
      userDetails.put("display-name", responseBody.getString("display-name"));
      userDetails.put("email", responseBody.getString("email"));

      return userDetails;
    } else {
      boolean hasBody = Integer.parseInt(
      conn.getRequestProperty("Content-Length")
      ) > 0;

      throw new CrowdApiException(
      "Error: "+conn.getResponseCode()+(
      hasBody ? responseBody.toString() : ""
      ));
    }
  }

  public Set<String> getUserGroups(String username) throws IOException, CrowdApiException {
    HashSet<String> set = new HashSet<String>();
    JsonObject responseBody = fetchGroupsResponse("direct", username);

    setGroups(set, responseBody);
    responseBody = fetchGroupsResponse("nested", username);
    setGroups(set, responseBody);

    return set;
  }

  private HttpsURLConnection createPostConnection(String path) throws MalformedURLException, IOException {
    HttpsURLConnection conn = (HttpsURLConnection)
    new URL(this.apiUrl+path).openConnection();

    String authString = Base64.getEncoder().encodeToString(
    (this.appName+":"+this.appPassword).getBytes("UTF-8")
    );

    if (!this.verifyCert) {
      conn.setHostnameVerifier(new HostnameVerifier() {
        @Override
        public boolean verify(String hostname, SSLSession session) {
          return true;
        }
      });
    }

    conn.setDoInput(true);
    conn.setDoOutput(true);
    conn.setRequestMethod("POST");
    conn.setRequestProperty("Accept", "application/json");
    conn.setRequestProperty("Content-Type", "application/json");
    conn.setRequestProperty("Authorization", "Basic "+authString);

    return conn;
  }

  private HttpsURLConnection createGetConnection(String path) throws MalformedURLException, IOException, UnsupportedEncodingException, ProtocolException {
    HttpsURLConnection conn = (HttpsURLConnection)
    new URL(this.apiUrl+path).openConnection();

    String authString = Base64.getEncoder().encodeToString(
    (this.appName+":"+this.appPassword).getBytes("UTF-8")
    );

    if (!this.verifyCert) {
      conn.setHostnameVerifier(new HostnameVerifier() {
        @Override
        public boolean verify(String hostname, SSLSession session) {
          return true;
        }
      });
    }

    conn.setDoInput(true);
    conn.setRequestMethod("GET");
    conn.setRequestProperty("Accept", "application/json");
    conn.setRequestProperty("Authorization", "Basic "+authString);

    return conn;
  }

  private JsonObject createAuthBody(String username, String password) {
    JsonBuilderFactory factory = Json.createBuilderFactory(null);
    return factory.createObjectBuilder()
    .add("username", username)
    .add("password", password)
    .add("validation-factors", factory.createObjectBuilder()
    .add("validationFactors", factory.createArrayBuilder()
    .add(factory.createObjectBuilder()
    .add("name", "remote_address")
    .add("value", "127.0.0.1")
    )
    )
    )
    .build();
  }

  private void writeBody(OutputStream stream, JsonObject body) throws UnsupportedEncodingException, IOException {
    BufferedWriter writer = new BufferedWriter(
      new OutputStreamWriter(stream, Charset.forName("UTF-8"))
    );

    writer.write(body.toString());
    writer.close();
  }

  private JsonObject readBody(InputStream stream) throws IOException {
    JsonReader reader = Json.createReader(stream);
    return reader.readObject();
  }

  private JsonObject fetchGroupsResponse(String type, String username) throws IOException, CrowdApiException {
    HttpsURLConnection conn = createGetConnection(
      "/usermanagement/1/user/group/"+type+"?username="+username
    );

    if (conn.getResponseCode() >= 200 || conn.getResponseCode() < 300) {
      return readBody(conn.getInputStream());
    } else {
      boolean hasBody = Integer.parseInt(
      conn.getRequestProperty("Content-Length")
      ) > 0;

      throw new CrowdApiException(
      "Error: "+conn.getResponseCode()+(
      hasBody ? readBody(conn.getInputStream()).toString() : ""
      ));
    }
  }

  private void setGroups(Set set, JsonObject body) {
    JsonArray groupArray = body.getJsonArray("groups");

    for (JsonValue value : groupArray) {
      set.add(value.asJsonObject().getString("name"));
    }
  }
}
