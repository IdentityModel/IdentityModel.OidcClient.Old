// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System;

namespace IdentityModel.OidcClient.Logging
{
    /// <summary>
    /// A no-op log provider to disable all logging
    /// </summary>
    public class NopLogProvider : ILogProvider
    {
        public static void Set()
        {
            LogProvider.SetCurrentLogProvider(new NopLogProvider());
        }

        /// <summary>
        ///  Nop logger
        /// </summary>
        /// <param name="name"></param>
        /// <returns></returns>
        public Logger GetLogger(string name)
        {
            return delegate { return false; };
        }

        /// <summary>
        ///  Nop logger
        /// </summary>
        /// <param name="key"></param>
        /// <param name="value"></param>
        /// <returns></returns>
        public IDisposable OpenMappedContext(string key, string value)
        {
            return new NoopClass();
        }

        /// <summary>
        ///  Nop logger
        /// </summary>
        /// <param name="message"></param>
        /// <returns></returns>
        public IDisposable OpenNestedContext(string message)
        {
            return new NoopClass();
        }

        private class NoopClass : IDisposable
        {
            public void Dispose()
            { }
        }
    }
}