using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(A4BusService.Startup))]
namespace A4BusService
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
