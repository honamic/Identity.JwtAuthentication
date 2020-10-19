using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Hosting;
using Microsoft.EntityFrameworkCore;
using Honamic.Identity.Jwt.Sample.Data;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.OpenApi.Models;
using System.IO;
using System;
using System.Linq;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Logging;
using System.Threading.Tasks;

namespace Honamic.Identity.Jwt.Sample
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddDbContext<ApplicationDbContext>(options =>
                options.UseSqlServer(
                    Configuration.GetConnectionString("DefaultConnection")));

            services.TryAddScoped<JwtSignInManager<IdentityUser, IdentityRole>>();
            services.TryAddScoped<UserClaimsPrincipalFactory<IdentityUser, IdentityRole>>();
            services.TryAddScoped<ITokenFactoryService<IdentityUser, IdentityRole>, TokenFactoryService<IdentityUser, IdentityRole>>();

            services.AddIdentity<IdentityUser, IdentityRole>(options =>
             {
                 options.SignIn.RequireConfirmedAccount = true;
                 options.Password.RequiredUniqueChars = 0;
                 options.Password.RequireDigit = false;
                 options.Password.RequireNonAlphanumeric = false;
                 options.Password.RequireUppercase = false;
             }).AddEntityFrameworkStores<ApplicationDbContext>()
             .AddDefaultUI();

            services.Configure<BearerTokensOptions>(options => Configuration.GetSection("BearerTokensOptions").Bind(options));
            var bearerTokensOptions = new BearerTokensOptions();
            Configuration.GetSection("BearerTokensOptions").Bind(bearerTokensOptions);

            services.AddControllers();
            services.AddRazorPages();

            services.AddSwaggerGen(setupAction =>
            {
                setupAction.SwaggerDoc(
                   name: "BackendOpenAPISpecification",
                   info: new Microsoft.OpenApi.Models.OpenApiInfo()
                   {
                       Title = "Identity Jwt",
                       Version = "1",
                       Description = "Identity jwt Sample Project"
                   });

                setupAction.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
                {
                    In = ParameterLocation.Header,
                    Description = "JWT Authorization header using the Bearer scheme. Example: \"Authorization: Bearer {token}\"",
                    Name = "Authorization",
                    Type = SecuritySchemeType.ApiKey
                });

                setupAction.AddSecurityRequirement(new OpenApiSecurityRequirement {
                   {
                     new OpenApiSecurityScheme
                     {
                       Reference = new OpenApiReference
                       {
                         Type = ReferenceType.SecurityScheme,
                         Id = "Bearer"
                       }
                      },
                      new string[] {"" }
                    }
                  });

                var xmlFiles = Directory.GetFiles(AppContext.BaseDirectory, "*.xml", SearchOption.TopDirectoryOnly).ToList();
                xmlFiles.ForEach(xmlFile => setupAction.IncludeXmlComments(xmlFile));

            });


            services.AddAuthentication()
                        .AddJwtBearer(cfg =>
                        {
                            cfg.RequireHttpsMetadata = false;
                            cfg.SaveToken = true;
                            cfg.TokenValidationParameters = new TokenValidationParameters
                            {
                                ValidIssuer = bearerTokensOptions.Issuer,
                                ValidAudience = bearerTokensOptions.Audience,
                                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(bearerTokensOptions.Key)),
                                ValidateIssuerSigningKey = true,
                                ValidateLifetime = true,
                                ClockSkew = TimeSpan.FromMinutes(3),
                                ValidateIssuer = true,
                                ValidateAudience = true,

                            };

                            cfg.Events = new JwtBearerEvents
                            {
                                OnAuthenticationFailed = context =>
                                {
                                    var logger = context.HttpContext.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger(nameof(JwtBearerEvents));
                                    logger.LogError("Authentication failed.", context.Exception);
                                    return Task.CompletedTask;
                                },
                                //OnTokenValidated = context =>
                                //{
                                //    var tokenValidatorService = context.HttpContext.RequestServices.GetRequiredService<ITokenValidatorService>();
                                //    return tokenValidatorService.ValidateAsync(context);
                                //},
                                OnMessageReceived = context =>
                                {
                                    return Task.CompletedTask;
                                },
                                OnChallenge = context =>
                                {
                                    var logger = context.HttpContext.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger(nameof(JwtBearerEvents));
                                    logger.LogError("OnChallenge error", context.Error, context.ErrorDescription);
                                    return Task.CompletedTask;
                                }
                            };
                        });
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                app.UseDatabaseErrorPage();
            }
            else
            {
                app.UseExceptionHandler("/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }

            app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseRouting();

            app.UseAuthentication();
            app.UseAuthorization();

            app.UseSwagger();
            app.UseSwaggerUI(setupAction =>
            {
                setupAction.SwaggerEndpoint(
                    url: "/swagger/BackendOpenAPISpecification/swagger.json",
                    name: "Backend API");
                setupAction.RoutePrefix = "swagger";
            });

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapRazorPages();
                endpoints.MapControllers();
            });
        }
    }
}
