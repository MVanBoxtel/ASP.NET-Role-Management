using System.Web;
using System.Web.Mvc;
// setup for assignment 4
// this project cannot be used to hand in as a student's work for assignemnts 1-3 
namespace A4BusService
{
    public class FilterConfig
    {
        public static void RegisterGlobalFilters(GlobalFilterCollection filters)
        {
            filters.Add(new HandleErrorAttribute());
        }
    }
}
