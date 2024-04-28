namespace SoftServerCinema.Security.ErrorFilter
{
    public class ApiException : Exception
    {
        public int StatusCode { get; set; }
        public string Title { get; set; }
        public string Detail { get; set; }

    }
}
