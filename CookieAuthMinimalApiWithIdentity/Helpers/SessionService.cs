using Microsoft.EntityFrameworkCore.Storage;
using Newtonsoft.Json;
using StackExchange.Redis;

namespace CookieAuthMinimalApiWithIdentity.Helpers
{
    public interface ICacheService
    {
        T GetData<T>(string key);

        bool SetData<T>(string key, T value, DateTimeOffset expirationTime);

        object RemoveData(string key);
    }

    public interface ISessionService
    {
        Guid GenerateSessionId();
    }
    public class SessionService : ISessionService, ICacheService
    {
        private StackExchange.Redis.IDatabase? _cache;
        private Guid _sessionId;
        public SessionService()
        {
            ConnectionMultiplexer connection = ConnectionMultiplexer.Connect("localhost");
            _cache = connection.GetDatabase();
        }
        public T GetData<T>(string key)
        {
            var value = _cache.StringGet(key);
            if (!string.IsNullOrEmpty(value))
            {
                return JsonConvert.DeserializeObject<T>(value);
            }
            return default;
        }
        public bool SetData<T>(string key, T value, DateTimeOffset expirationTime)
        {
            TimeSpan expiryTime = expirationTime.DateTime.Subtract(DateTime.Now);
            var isSet = _cache.StringSet(key, JsonConvert.SerializeObject(value), expiryTime);
            return isSet;
        }
        public object RemoveData(string key)
        {
            bool _isKeyExist = _cache.KeyExists(key);
            if (_isKeyExist == true)
            {
                return _cache.KeyDelete(key);
            }
            return false;
        }

        public Guid GenerateSessionId()
        {
            this._sessionId = Guid.NewGuid();
            return this._sessionId;
        }
    }
}
