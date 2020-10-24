using Honamic.Identity.JwtAuthentication;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Text;
using System.Threading.Tasks;

namespace Microsoft.Extensions.DependencyInjection
{
    public static class JwtAuthenticationExtensions
    {

        public static AuthenticationBuilder AddJwtAuthentication<TUser>(this AuthenticationBuilder builder, IConfiguration configuration)
            where TUser : class
        {

            builder.Services.TryAddScoped<JwtSignInManager<TUser>>();

            builder.Services.TryAddScoped<ITokenFactoryService<TUser>, TokenFactoryService<TUser>>();

            builder.Services.AddOptions<JwtAuthenticationOptions>()
                .Bind(configuration.GetSection(nameof(JwtAuthenticationOptions)))
                .ValidateDataAnnotations();

            var bearerTokensOptions = configuration.GetSection(nameof(JwtAuthenticationOptions)).Get<JwtAuthenticationOptions>();

            builder.AddJwtBearer(cfg =>
            {
                cfg.RequireHttpsMetadata = false;
                cfg.SaveToken = true;
                cfg.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidIssuer = bearerTokensOptions.Issuer,
                    ValidAudience = bearerTokensOptions.Audience,
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(bearerTokensOptions.SigningKey)),
                    TokenDecryptionKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(bearerTokensOptions.EncrtyptKey)),
                    ValidateIssuerSigningKey = true,
                    ValidateLifetime = true,
                    ClockSkew = TimeSpan.FromSeconds(bearerTokensOptions.ClockSkewSeconds),
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
                    OnTokenValidated = context =>
                    {
                        var JwtSignInManager = context.HttpContext.RequestServices.GetRequiredService<JwtSignInManager<TUser>>();
                        return JwtSignInManager.ValidateSecurityStampAsync(context);
                    },
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


            builder.AddJwtBearer(JwtAuthenticationOptions.JwtBearerTwoFactorsScheme, cfg =>
           {
               cfg.RequireHttpsMetadata = false;
               cfg.SaveToken = true;
               cfg.TokenValidationParameters = new TokenValidationParameters
               {
                   ValidIssuer = bearerTokensOptions.Issuer,
                   ValidAudience = bearerTokensOptions.Audience,
                   IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(bearerTokensOptions.SigningKey)),
                   TokenDecryptionKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(bearerTokensOptions.EncrtyptKey)),
                   ValidateIssuerSigningKey = true,
                   ValidateLifetime = true,
                   ClockSkew = TimeSpan.FromSeconds(bearerTokensOptions.ClockSkewSeconds),
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
                   OnTokenValidated = context =>
                   {
                       return Task.CompletedTask;
                   },
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


            return builder;
        }
    }
}
