package org.opensourceway.uvp.controller;

import io.swagger.v3.oas.annotations.Hidden;
import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.enums.ParameterIn;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.media.ArraySchema;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.opensourceway.uvp.api.Example;
import org.opensourceway.uvp.api.HttpStatusCode;
import org.opensourceway.uvp.constant.UvpConstant;
import org.opensourceway.uvp.enums.ErrorCode;
import org.opensourceway.uvp.exception.InvalidPurlException;
import org.opensourceway.uvp.pojo.osv.OsvVulnerability;
import org.opensourceway.uvp.pojo.request.SearchRequest;
import org.opensourceway.uvp.pojo.response.Error;
import org.opensourceway.uvp.pojo.response.PackageVulns;
import org.opensourceway.uvp.pojo.response.SearchResp;
import org.opensourceway.uvp.pojo.response.VulnDetailResp;
import org.opensourceway.uvp.service.UvpService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.List;
import java.util.Objects;

import static org.springframework.util.MimeTypeUtils.APPLICATION_JSON_VALUE;

@Controller
@RequestMapping(path = "/uvp-api")
@OpenAPIDefinition(info = @Info(title = "UVP API", version = "0.0.1",
        description = "API to query vulnerabilities via PURL"))
public class UvpController {
    private static final Logger logger = LoggerFactory.getLogger(UvpController.class);

    @Autowired
    private UvpService uvpService;

    @Operation(summary = "Query vulnerabilities affecting a given PURL")
    @Parameter(
            name = "purl",
            in = ParameterIn.QUERY,
            description = "Package URL",
            required = true,
            example = Example.PURL_EXAMPLE)
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = HttpStatusCode.OK,
                    description = "A JSON list of OSV schema vulnerabilities",
                    content = @Content(
                            mediaType = APPLICATION_JSON_VALUE,
                            array = @ArraySchema(schema = @Schema(implementation = OsvVulnerability.class)),
                            examples = @ExampleObject(value = Example.OSV_VULN_EXAMPLE))),
            @ApiResponse(
                    responseCode = HttpStatusCode.BAD_REQUEST,
                    description = "Invalid PURL",
                    content = @Content(
                            mediaType = APPLICATION_JSON_VALUE,
                            schema = @Schema(implementation = Error.class),
                            examples = @ExampleObject(value = Example.ERROR_INVALID_PURL_EXAMPLE))),
            @ApiResponse(
                    responseCode = HttpStatusCode.INTERNAL_SERVER_ERROR,
                    description = "There was an internal error while process the request",
                    content = @Content(
                            mediaType = APPLICATION_JSON_VALUE,
                            schema = @Schema(implementation = Error.class),
                            examples = @ExampleObject(value = Example.ERROR_INTERNAL_EXAMPLE)))
    })
    @Tag(name = "API")
    @GetMapping(value = "/query", produces = APPLICATION_JSON_VALUE)
    public @ResponseBody ResponseEntity<?> query(@RequestParam String purl) {
        logger.info("Query vulns by: <{}>", purl);

        List<OsvVulnerability> result;
        try {
            result = uvpService.query(purl);
        } catch (InvalidPurlException e) {
            logger.error(e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new Error(ErrorCode.INVALID_PURL, e.getMessage()));
        } catch (Exception e) {
            logger.error("Unknown error occurs", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new Error(ErrorCode.UNKNOWN, "Unknown error"));
        }

        logger.info("Query successfully with result size: <{}>", result.size());
        return ResponseEntity.status(HttpStatus.OK).body(result);
    }

    @Operation(summary = "Query vulnerabilities affecting a given list of PURLs")
    @io.swagger.v3.oas.annotations.parameters.RequestBody(
            description = "A JSON list of Package URLs",
            required = true,
            content = @Content(
                    mediaType = APPLICATION_JSON_VALUE,
                    array = @ArraySchema(
                            schema = @Schema(implementation = String.class),
                            maxItems = UvpConstant.QUERY_BATCH_LIMIT),
                    examples = @ExampleObject(value = Example.PURL_LIST_EXAMPLE)))
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = HttpStatusCode.OK,
                    description = "A JSON list of Package URLs and their corresponding OSV schema vulnerabilities",
                    content = @Content(
                            mediaType = APPLICATION_JSON_VALUE,
                            array = @ArraySchema(schema = @Schema(implementation = PackageVulns.class)),
                            examples = @ExampleObject(value = Example.PKG_VULNS_EXAMPLE))),
            @ApiResponse(
                    responseCode = HttpStatusCode.BAD_REQUEST,
                    description = "There are some invalid PURLs",
                    content = @Content(
                            mediaType = APPLICATION_JSON_VALUE,
                            schema = @Schema(implementation = Error.class),
                            examples = @ExampleObject(value = Example.ERROR_INVALID_PURL_LIST_EXAMPLE))),
            @ApiResponse(
                    responseCode = HttpStatusCode.INTERNAL_SERVER_ERROR,
                    description = "There was an internal error while process the request",
                    content = @Content(
                            mediaType = APPLICATION_JSON_VALUE,
                            schema = @Schema(implementation = Error.class),
                            examples = @ExampleObject(value = Example.ERROR_INTERNAL_EXAMPLE)))
    })
    @Tag(name = "API")
    @PostMapping(value = "/queryBatch", consumes = APPLICATION_JSON_VALUE, produces = APPLICATION_JSON_VALUE)
    public @ResponseBody ResponseEntity<?> queryBatch(@RequestBody List<String> purls) {
        logger.info("Batch query vulns by: <{}>", purls);

        if (purls.size() > UvpConstant.QUERY_BATCH_LIMIT) {
            var errorMessage = "Query size <%s> exceeds the threshold <%s>"
                    .formatted(purls.size(), UvpConstant.QUERY_BATCH_LIMIT);
            logger.error(errorMessage);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new Error(ErrorCode.QUERY_SIZE_EXCEEDS, errorMessage));
        }

        List<PackageVulns> result;
        try {
            result = uvpService.queryBatch(purls);
        } catch (InvalidPurlException e) {
            logger.error(e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new Error(ErrorCode.INVALID_PURL, e.getMessage()));
        } catch (Exception e) {
            logger.error("Unknown error occurs", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new Error(ErrorCode.UNKNOWN, "Unknown error"));
        }

        logger.info("Batch query successfully, get <{}> vulns for <{}> purls.",
                result.stream().map(PackageVulns::vulns).mapToLong(List::size).sum(), purls.size());
        return ResponseEntity.status(HttpStatus.OK).body(result);
    }

    @Hidden
    @PostMapping("/importBatch")
    public @ResponseBody ResponseEntity<?> importBatch(@RequestBody List<String> purls) {
        logger.info("Batch import... size: <{}>", purls.size());

        try {
            uvpService.importBatch(purls);
        } catch (InvalidPurlException e) {
            logger.error(e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new Error(ErrorCode.INVALID_PURL, e.getMessage()));
        } catch (Exception e) {
            logger.error("Unknown error occurs", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new Error(ErrorCode.UNKNOWN, "Unknown error"));
        }

        logger.info("Batch import successfully");
        return ResponseEntity.status(HttpStatus.OK).body("Batch import successfully");
    }

    @Hidden
    @Operation(summary = "Search vulnerabilities by a given keyword")
    @io.swagger.v3.oas.annotations.parameters.RequestBody(
            description = "Search request that consists of `keyword`, `page`, `size`",
            content = @Content(
                    mediaType = APPLICATION_JSON_VALUE,
                    schema = @Schema(implementation = SearchRequest.class),
                    examples = @ExampleObject(value = Example.SEARCH_REQUEST_EXAMPLE)))
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = HttpStatusCode.OK,
                    description = "A JSON list of summaries of the matched vulnerabilities, " +
                            "and a flag indicates whether the current page is the last",
                    content = @Content(
                            mediaType = APPLICATION_JSON_VALUE,
                            array = @ArraySchema(schema = @Schema(implementation = SearchResp.class)),
                            examples = @ExampleObject(value = Example.SEARCH_RESP_EXAMPLE))),
            @ApiResponse(
                    responseCode = HttpStatusCode.BAD_REQUEST,
                    description = "Illegal request",
                    content = @Content(
                            mediaType = APPLICATION_JSON_VALUE,
                            schema = @Schema(implementation = Error.class),
                            examples = @ExampleObject(value = Example.ERROR_ILLEGAL_ARGUMENT_EXAMPLE))),
            @ApiResponse(
                    responseCode = HttpStatusCode.INTERNAL_SERVER_ERROR,
                    description = "There was an internal error while process the request",
                    content = @Content(
                            mediaType = APPLICATION_JSON_VALUE,
                            schema = @Schema(implementation = Error.class),
                            examples = @ExampleObject(value = Example.ERROR_INTERNAL_EXAMPLE)))
    })
    @PostMapping("/search")
    public @ResponseBody ResponseEntity<?> search(@RequestBody(required = false) SearchRequest request) {
        logger.info("Search vulns by: <{}>", request);
        if (Objects.isNull(request)) {
            request = new SearchRequest();
        }

        if (Objects.isNull(request.getKeyword())) {
            request.setKeyword("");
        }

        SearchResp resp;
        try {
            resp = uvpService.search(request);
        } catch (IllegalArgumentException e) {
            logger.error(e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new Error(ErrorCode.ILLEGAL_ARGUMENT, e.getMessage()));
        } catch (Exception e) {
            logger.error("Unknown error occurs when search vulns by: <{}>", request, e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new Error(ErrorCode.UNKNOWN, "Unknown error"));
        }

        logger.info("Search vulns by: <{}> successfully, get <{}> vulns",
                request, Objects.isNull(resp) ? 0 : resp.getVulns().size());
        return ResponseEntity.status(HttpStatus.OK).body(resp);
    }

    @Hidden
    @Operation(summary = "Query details for a given vulnerability")
    @Parameter(
            name = "vulnId",
            in = ParameterIn.PATH,
            description = "Vulnerability ID, such as CVE ID, GHSA ID",
            required = true,
            example = Example.VULN_ID_EXAMPLE)
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = HttpStatusCode.OK,
                    description = "A JSON object of details for a vulnerability",
                    content = @Content(
                            mediaType = APPLICATION_JSON_VALUE,
                            schema = @Schema(implementation = VulnDetailResp.class),
                            examples = @ExampleObject(value = Example.VULN_DETAIL_EXAMPLE))),
            @ApiResponse(
                    responseCode = HttpStatusCode.BAD_REQUEST,
                    description = "There is no details for the requested vulnerability ID",
                    content = @Content(
                            mediaType = APPLICATION_JSON_VALUE,
                            schema = @Schema(implementation = Error.class),
                            examples = @ExampleObject(value = Example.INVALID_VULN_DETAIL_EXAMPLE))),
            @ApiResponse(
                    responseCode = HttpStatusCode.INTERNAL_SERVER_ERROR,
                    description = "There was an internal error while process the request",
                    content = @Content(
                            mediaType = APPLICATION_JSON_VALUE,
                            schema = @Schema(implementation = Error.class),
                            examples = @ExampleObject(value = Example.ERROR_INTERNAL_EXAMPLE)))
    })
    @GetMapping("/vulnerability/{vulnId}")
    public @ResponseBody ResponseEntity<?> queryVulnDetail(@PathVariable String vulnId) {
        logger.info("Query details for vulnerability: <{}>", vulnId);

        VulnDetailResp resp;
        try {
            resp = uvpService.queryVulnDetail(vulnId);
        } catch (Exception e) {
            logger.error("Unknown error occurs when query detail for vulnerability: <{}>", vulnId, e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new Error(ErrorCode.UNKNOWN, "Unknown error"));
        }

        if (Objects.isNull(resp)) {
            logger.error("Vulnerability with id <{}> doesn't exist", vulnId);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new Error(ErrorCode.INVALID_VULN_ID, "Invalid vulnerability ID: <%s>".formatted(vulnId)));
        }

        logger.info("Query details successfully for vulnerability: <{}>", vulnId);
        return ResponseEntity.status(HttpStatus.OK).body(resp);
    }
}
