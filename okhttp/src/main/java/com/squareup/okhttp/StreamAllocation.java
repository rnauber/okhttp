/*
 * Copyright (C) 2015 Square, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.squareup.okhttp;

/** Links a stream to a connection. */
// TODO(jwilson): move this to internal once dust has all settled.
public final class StreamAllocation {
  private final Connection connection;

  /** True if the call is done with this allocation. */
  boolean released;

  /**
   * Non-null if a stream is using this allocation. This may be non-null even after the
   * allocation has been released, because the application may continue to read the response body
   * long after redirects and authorization challenges have all been handled.
   */
  Object stream;

  /**
   * True if this allocation has been taken away by the connection. The current stream may
   * proceed but further streams need new allocations.
   */
  boolean rescinded;

  public StreamAllocation(Connection connection) {
    this.connection = connection;
  }

  /** Returns true if a new stream is permitted or null if this allocation has been rescinded. */
  public boolean newStream(Object stream) {
    synchronized (connection.pool) {
      if (this.stream != null || released) throw new IllegalStateException();
      if (rescinded) return false;
      this.stream = stream;
      return true;
    }
  }

  public void noNewStreams() {
    connection.noNewStreams();
  }

  public void streamComplete(Object stream) {
    synchronized (connection.pool) {
      if (stream == null || stream != this.stream) throw new IllegalArgumentException();
      this.stream = null;
      if (released) {
        connection.remove(this);
      }
    }
  }

  @Override public String toString() {
    return connection.toString();
  }
}
